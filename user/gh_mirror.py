"""gh_mirror.py —— GitHub 下载多源加速（竞速 + 校验 + 记忆）

为什么单独一个模块：
    update_check 只查 API（几 KB 的 JSON，直连就够），真正会卡住的是 Release 资产
    和源码包。国内直连 github.com 的下载经常几 KB/s 或者直接被 reset，而公共加速站
    都是「前缀代理」（https://站点/https://github.com/...），可用性天天在变，
    所以不能写死一个站点，必须多源 + 校验 + 记住谁快。

三条必须守住的规则（都是踩出来的）：
    1. **不能只看 HTTP 状态码**。实测 gh-proxy.net / gitproxy.click / ghps.cc 这些
       站点会返回 200 + 一个 HTML 拦截页，看着成功、内容全错。必须校验内容。
    2. **校验优先于速度**。竞速时任何一个源返回的东西都要过「大小 / sha256 /
       gzip 魔数 / 不是网页」四道检查，不合格就当这个源失败，换下一个。
    3. **直连也是候选**。你这台机器实测直连 1.1 MB/s 比大部分加速站都快，
       无条件镜像优先反而更慢。竞速让两者同时起跑，谁快用谁。

用法（命令行）：
    python user\\gh_mirror.py --test                     # 测速体检
    python user\\gh_mirror.py --list                     # 看候选源与历史成绩
    python user\\gh_mirror.py --url <URL> --out <文件>    # 手动下载（自动选源）

用法（代码）：
    import gh_mirror
    r = gh_mirror.download(url, dest, expect_size=asset["size"], sha256=want)
    print(r["source"], r["bytes"], r["seconds"])

模式（也可以用环境变量 SYGUARD_MIRROR 指定）：
    auto    默认。直连 + 镜像同时竞速，谁先拿到合格数据用谁
    mirror  只用镜像站，直连不参与（适合 GitHub 完全连不上的网络）
    off     只用直连
    <前缀>  指定站点，多个用逗号隔开，如 https://gh.monlor.com/,https://gh-proxy.org/

退出码：0 成功 / 1 失败 / 2 参数问题
"""

import hashlib
import json
import os
import queue
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

# ---------------- 可配置项 ----------------
REPO = "23z702/windows-sysguard"

# 顺序不代表优先级（竞速时是一起起跑的），但决定了「最多几个同时跑」时谁进场。
# 候选来自 2026-11 实测：能返回正确内容的留下，其余全部剔除（见文件尾注释）。
MIRRORS = [
    "https://gh.monlor.com/",
    "https://gh-proxy.org/",
    "https://cors.isteed.cc/",
    "https://gh-proxy.com/",
    "https://ghfast.top/",
]

# 能走前缀代理的域名；api.github.com 不在里面——API 请求很小，且大部分镜像不代理 API
MIRROR_HOSTS = (
    "github.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "gist.github.com",
)

UA = "sysguard-gh-mirror/1.0 (+https://github.com/%s)" % REPO
MAX_RACE = 3              # 同时起跑的源数量，其余作为串行兜底
CHUNK = 1 << 16
HTML_HEAD = 512

CACHE_DIR = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "sysguard")
STATS_PATH = os.path.join(CACHE_DIR, "mirrors.json")
STATS_TTL = 7 * 86400     # 成绩保留 7 天，过期重新计


class MirrorFail(Exception):
    """所有源都失败（消息直接给用户看）。"""


class _Reject(Exception):
    """这个源不能用（内容不对 / 假 200 / 大小不符），换下一个。"""


class _Abort(Exception):
    """被更快的源抢先，放弃本次。"""


# ---------------- 候选源 ----------------
def _is_mirrorable(url):
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    return host in MIRROR_HOSTS


def _custom_mirrors():
    """环境变量 > 成绩文件里的 custom > 内置列表。"""
    env = os.environ.get("SYGUARD_MIRRORS", "").strip()
    if env:
        return [x.strip() for x in env.split(",") if x.strip()]
    st = _load_stats()
    custom = st.get("custom")
    if isinstance(custom, list) and custom:
        return [str(x) for x in custom if str(x).startswith("http")]
    return list(MIRRORS)


def _norm_prefix(p):
    p = p.strip()
    if not p:
        return ""
    if not p.startswith(("http://", "https://")):
        p = "https://" + p
    return p if p.endswith("/") else p + "/"


def sources(url, mode=None):
    """返回 [(显示名, 实际URL)]，按「该先试谁」排好序。"""
    if not _is_mirrorable(url):
        return [("直连", url)]

    mode = (mode or os.environ.get("SYGUARD_MIRROR") or "auto").strip()
    low = mode.lower()

    if low in ("off", "direct", "0", "no", "false"):
        return [("直连", url)]

    mirrors = [_norm_prefix(m) for m in _custom_mirrors()]
    mirrors = [m for m in mirrors if m]

    if low == "mirror":
        if not mirrors:
            return [("直连", url)]
        return [(m, m + url) for m in _rank(mirrors)]

    if low in ("auto", "on", "1", "yes", "true", ""):
        cands = [("直连", url)] + [(m, m + url) for m in _rank(mirrors)]
        return cands

    # 自定义：mode 本身就是一个或多个前缀
    picked = [_norm_prefix(x) for x in re.split(r"[,;\s]+", mode) if x.strip()]
    picked = [p for p in picked if p.startswith("http")]
    if not picked:
        return [("直连", url)]
    return [(p, p + url) for p in picked] + [("直连", url)]


def _rank(mirrors):
    """按历史成绩排序：成功过的、快的排前面；没记录的保持原顺序。"""
    st = _load_stats().get("sources") or {}
    now = time.time()

    def key(m):
        rec = st.get(m) or {}
        age = now - float(rec.get("ts") or 0)
        if rec.get("ok") and age < STATS_TTL and rec.get("ms"):
            return (0, float(rec["ms"]))
        if rec.get("fail") and age < STATS_TTL:
            return (2, 0.0)
        return (1, 0.0)

    return sorted(mirrors, key=key)


# ---------------- 成绩记录 ----------------
def _load_stats():
    try:
        with open(STATS_PATH, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_stats(d):
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        tmp = STATS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
        os.replace(tmp, STATS_PATH)
    except OSError:
        pass


def note_result(name, ok, seconds=0.0, size=0):
    """记一次成绩。name 是显示名（镜像前缀或「直连」）。"""
    if not name:
        return
    d = _load_stats()
    src = d.setdefault("sources", {})
    rec = src.setdefault(name, {})
    if ok:
        rec["ok"] = int(rec.get("ok") or 0) + 1
        rec["ms"] = int(seconds * 1000)
        rec["bytes"] = int(size)
        rec["fail"] = 0
        rec["error"] = ""
    else:
        rec["fail"] = int(rec.get("fail") or 0) + 1
        rec["error"] = str(seconds)[:120]
    rec["ts"] = int(time.time())
    _save_stats(d)


# ---------------- 单源下载 ----------------
def _looks_html(head):
    h = head.lstrip()[:256].lower()
    if not h:
        return False
    return (h.startswith(b"<!doctype") or h.startswith(b"<html")
            or h.startswith(b"<head") or h.startswith(b"<?xml")
            or b"<title>" in h[:160])


def _stream(url, tmp, timeout, stop=None, expect_size=0, sha256=None,
            is_tar=False, label="", quiet=True):
    """把一个源的内容完整下到 tmp 并做内容校验。不合格抛 _Reject。"""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    h = hashlib.sha256()
    total = 0
    head = b""

    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        raise _Reject("HTTP %s" % e.code)
    except urllib.error.URLError as e:
        raise _Reject("连不上：%s" % getattr(e, "reason", e))
    except (OSError, TimeoutError) as e:
        raise _Reject("连接失败：%s" % e.__class__.__name__)

    with resp:
        declared = 0
        try:
            declared = int(resp.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            declared = 0

        # 长度对不上不用下完，直接换源（假 200 大多死在这一步）
        if expect_size and declared and declared != expect_size:
            raise _Reject("大小不符（%d ≠ %d），可能是拦截页" % (declared, expect_size))

        started = time.time()
        try:
            with open(tmp, "wb") as f:
                while True:
                    if stop is not None and stop.is_set():
                        raise _Abort()
                    chunk = resp.read(CHUNK)
                    if not chunk:
                        break
                    if len(head) < HTML_HEAD:
                        head += chunk[:HTML_HEAD - len(head)]
                        if total == 0 and _looks_html(head):
                            raise _Reject("返回的是网页，不是文件")
                    f.write(chunk)
                    h.update(chunk)
                    total += len(chunk)
                    if (not quiet) and declared and sys.stdout.isatty():
                        sys.stdout.write("\r  %-22s %5.1f%%  %5.1f/%.1f KB"
                                         % (label or "下载", 100.0 * total / declared,
                                            total / 1024.0, declared / 1024.0))
                        sys.stdout.flush()
        except (_Abort, _Reject):
            raise
        except (OSError, TimeoutError) as e:
            raise _Reject("传输中断：%s" % e.__class__.__name__)

        if not quiet and declared and sys.stdout.isatty():
            sys.stdout.write("\n")

    if total == 0:
        raise _Reject("下到 0 字节")
    if expect_size and total != expect_size:
        raise _Reject("大小不符（%d ≠ %d）" % (total, expect_size))

    if is_tar:
        with open(tmp, "rb") as f:
            magic = f.read(2)
        if magic != b"\x1f\x8b":
            raise _Reject("不是 gzip 包（魔数 %r）" % magic)

    got = h.hexdigest()
    if sha256 and got.lower() != sha256.lower():
        raise _Reject("sha256 不符（%s… ≠ %s…）" % (got[:12], sha256[:12]))
    return {"bytes": total, "sha256": got, "seconds": time.time() - started}


# ---------------- 对外：下载 ----------------
def download(url, dest, timeout=120, label="", mode=None, expect_size=0,
             sha256=None, is_tar=False, quiet=True, log=None):
    """多源下载到 dest。返回 dict：path/source/bytes/seconds/sha256/tries。

    失败抛 MirrorFail（带每个源的原因），不会留下半截文件。
    """
    log = log or (lambda *_a, **_k: None)
    dest = os.path.abspath(dest)
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)

    # 已经下过且能校验通过，直接用（省流量，也让重跑更新时不必再走网络）
    if os.path.isfile(dest):
        if _verify_existing(dest, expect_size, sha256, is_tar):
            log("  已有完整文件，跳过下载：%s" % os.path.basename(dest))
            return {"path": dest, "source": "缓存", "bytes": os.path.getsize(dest),
                    "seconds": 0.0, "sha256": sha256 or _sha256_file(dest), "tries": []}

    cands = sources(url, mode)
    if not cands:
        raise MirrorFail("没有可用的下载源")

    tries = []
    race_n = min(len(cands), max(1, int(os.environ.get("SYGUARD_RACE") or MAX_RACE)))
    start = 0

    # 第一梯队：并发竞速
    if race_n > 1:
        start = race_n
        best, errs = _race(cands[:race_n], dest, timeout, label, expect_size,
                           sha256, is_tar, quiet)
        tries.extend(errs)
        if best:
            for name, why in errs:
                log("  [x] %-30s %s" % (name, why))
            log("  [√] %-30s %.2fs  %.0f KB"
                % (best["source"], best["seconds"], best["bytes"] / 1024.0))
            note_result(best["source"], True, best["seconds"], best["bytes"])
            return best

    # 第二梯队：剩下的顺序试（前面的全挂了才走到这）
    for name, u in cands[start:]:
        tmp = dest + ".part"
        t0 = time.time()
        try:
            r = _stream(u, tmp, timeout, expect_size=expect_size, sha256=sha256,
                        is_tar=is_tar, label=label, quiet=quiet)
        except (_Reject, _Abort) as e:
            _rm(tmp)
            tries.append((name, str(e) or "rejected"))
            note_result(name, False, 0)
            log("  [x] %-30s %s" % (name, e))
            continue
        os.replace(tmp, dest)
        note_result(name, True, r["seconds"], r["bytes"])
        log("  [√] %-30s %.2fs  %.0f KB" % (name, r["seconds"], r["bytes"] / 1024.0))
        return {"path": dest, "source": name, "bytes": r["bytes"],
                "seconds": r["seconds"], "sha256": r["sha256"], "tries": tries}

    # 先试第一梯队里最快的那个，但已经全失败，汇总报错
    detail = "；".join("%s: %s" % (n, w) for n, w in tries) or "全部源无响应"
    raise MirrorFail("下载失败（试了 %d 个源）—— %s" % (len(tries), detail))


def _race(cands, dest, timeout, label, expect_size, sha256, is_tar, quiet):
    """并发竞速：第一个拿到合格文件的源获胜，其余立即放弃。"""
    q = queue.Queue()
    stop = threading.Event()
    tmps = {}
    lock = threading.Lock()

    def worker(idx, name, u):
        tmp = "%s.part%d" % (dest, idx)
        with lock:
            tmps[idx] = tmp
        try:
            r = _stream(u, tmp, timeout, stop=stop, expect_size=expect_size,
                        sha256=sha256, is_tar=is_tar, label=name, quiet=True)
            if stop.is_set():
                _rm(tmp)
                return
            q.put(("ok", name, tmp, r, None))
        except _Abort:
            _rm(tmp)
            q.put(("abort", name, None, None, "被更快的源抢先"))
        except _Reject as e:
            _rm(tmp)
            q.put(("bad", name, None, None, str(e) or "rejected"))
        except Exception as e:                       # 兜底：一个源崩了不能拖垮整体
            _rm(tmp)
            q.put(("bad", name, None, None, "%s: %s" % (e.__class__.__name__, e)))

    threads = [threading.Thread(target=worker, args=(i, n, u), daemon=True)
               for i, (n, u) in enumerate(cands)]
    for t in threads:
        t.start()

    winner, errs, winner_tmp = None, [], ""
    got = 0
    deadline = time.time() + max(15.0, min(timeout + 10.0, 60.0))
    while got < len(cands):
        left = deadline - time.time()
        if left <= 0:
            errs.append(("(竞速)", "超过 %.0fs 没有源完成" % (deadline - time.time() + left)))
            break
        try:
            kind, name, tmp, r, why = q.get(timeout=left)
        except queue.Empty:
            errs.append(("(超时)", "等不到任何源"))
            break
        got += 1
        if kind == "ok":
            winner = {"path": dest, "source": name, "bytes": r["bytes"],
                      "seconds": r["seconds"], "sha256": r["sha256"], "tries": []}
            winner_tmp = tmp
            stop.set()
            break
        if kind == "bad":
            errs.append((name, why))

    if winner and winner_tmp and os.path.isfile(winner_tmp):
        os.replace(winner_tmp, dest)
        winner["tries"] = errs
        _cleanup(tmps, keep=None)     # 其余临时文件（可能被占用，删不掉就算了）
        return winner, errs
    return None, errs


def _cleanup(tmps, keep=None):
    for _idx, p in list(tmps.items()):
        if keep and p == keep:
            continue
        _rm(p)


def _verify_existing(path, expect_size, sha256, is_tar):
    try:
        size = os.path.getsize(path)
    except OSError:
        return False
    if size <= 0:
        return False
    if expect_size and size != expect_size:
        return False
    if is_tar:
        with open(path, "rb") as f:
            if f.read(2) != b"\x1f\x8b":
                return False
    if sha256:
        return _sha256_file(path).lower() == sha256.lower()
    return True


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _rm(path):
    try:
        if path and os.path.isfile(path):
            os.unlink(path)
    except OSError:
        pass


# ---------------- 体检 ----------------
PROBE_URL = "https://github.com/%s/archive/refs/heads/main.tar.gz" % REPO


def probe(timeout=10, url=PROBE_URL):
    """并发测每个源，返回按耗时排好的结果。"""
    cands = sources(url, mode="auto")
    out = []
    lock = threading.Lock()

    def one(name, u):
        fd, tmp = tempfile.mkstemp(prefix="ghprobe-")
        os.close(fd)
        t0 = time.time()
        try:
            r = _stream(u, tmp, timeout, is_tar=True, quiet=True)
            with lock:
                out.append({"name": name, "ok": True, "ms": int(r["seconds"] * 1000),
                            "kb": r["bytes"] / 1024.0, "error": ""})
            note_result(name, True, r["seconds"], r["bytes"])
        except Exception as e:
            with lock:
                out.append({"name": name, "ok": False,
                            "ms": int((time.time() - t0) * 1000), "kb": 0.0,
                            "error": str(e) or e.__class__.__name__})
            note_result(name, False, 0)
        finally:
            _rm(tmp)

    threads = [threading.Thread(target=one, args=(n, u), daemon=True) for n, u in cands]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout + 5)
    return sorted(out, key=lambda x: (not x["ok"], x["ms"]))


def _print_probe(rows):
    print("%-32s %-6s %8s %8s  %s" % ("源", "状态", "耗时", "大小", "备注"))
    print("-" * 78)
    for r in rows:
        print("%-32s %-6s %7dms %7.1fKB  %s"
              % (r["name"], "OK" if r["ok"] else "失效", r["ms"], r["kb"],
                 (r["error"] or "")[:34]))
    ok = [r for r in rows if r["ok"]]
    if ok:
        print("\n最快：%s（%dms）　可用 %d/%d"
              % (ok[0]["name"], ok[0]["ms"], len(ok), len(rows)))
    else:
        print("\n所有源都不可用 —— 检查网络，或用 --mode off 试直连")
    print("成绩已记录：%s" % STATS_PATH)


def _print_list():
    mirrors = _custom_mirrors()
    st = _load_stats().get("sources") or {}
    print("候选源（%d 个，可用 SYGUARD_MIRRORS 环境变量或 mirrors.json 的 custom 覆盖）\n" % len(mirrors))
    for m in _rank(mirrors):
        rec = st.get(m) or {}
        if rec.get("ok"):
            tail = "成功 %s 次，最近 %sms" % (rec.get("ok"), rec.get("ms"))
        elif rec.get("fail"):
            tail = "最近失败：%s" % (rec.get("error") or "")[:40]
        else:
            tail = "还没测过"
        print("  %-34s %s" % (m, tail))
    print("  %-34s %s" % ("(直连)", "始终参与竞速，可用 --mode off 强制只用它"))


# ---------------- 命令行 ----------------
def main(argv):
    mode = None
    url = out = None
    do_probe = do_list = False

    for i, a in enumerate(argv):
        if a == "--test":
            do_probe = True
        elif a == "--list":
            do_list = True
        elif a == "--mode" and i + 1 < len(argv):
            mode = argv[i + 1]
        elif a == "--url" and i + 1 < len(argv):
            url = argv[i + 1]
        elif a == "--out" and i + 1 < len(argv):
            out = argv[i + 1]
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0

    if do_list:
        _print_list()
        return 0

    if do_probe:
        if mode:
            os.environ["SYGUARD_MIRROR"] = mode
        print("正在并发测速（每个源下载一次仓库源码包）…\n")
        rows = probe()
        _print_probe(rows)
        return 0 if any(r["ok"] for r in rows) else 1

    if url:
        if not out:
            out = os.path.join(os.getcwd(), url.rstrip("/").rsplit("/", 1)[-1] or "download")
        try:
            r = download(url, out, mode=mode, quiet=False, log=print,
                         is_tar=url.endswith((".tar.gz", ".tgz")))
        except MirrorFail as e:
            print("\n[失败] %s" % e, file=sys.stderr)
            return 1
        print("\n完成：%s（%s，%.0f KB，%.2fs）"
              % (r["path"], r["source"], r["bytes"] / 1024.0, r["seconds"]))
        return 0

    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


# ---------------- 2026-11 实测记录（改列表前先看这里） ----------------
# 可用（返回真实内容）：
#   https://gh.monlor.com/      1.7s 建连，2MB 用 3.2s
#   https://gh-proxy.org/       1.8s 建连，2MB 用 3.5s
#   https://cors.isteed.cc/     1.6s 建连，2MB 用 2.6s（其实是通用 CORS 代理，顺带支持）
#   https://gh-proxy.com/       2.3s 建连，2MB 用 13s  ← 能通但很慢，排在后面
#   https://ghfast.top/         小文件能通，2MB 直接超时  ← 兜底用
# 返回 200 但内容是 HTML 拦截页（必须靠内容校验识破，否则会把网页当 .sys 写进去）：
#   https://gh-proxy.net/  https://gitproxy.click/  https://ghps.cc/
# 已失效（DNS 或连接失败，别再放回列表白等超时）：
#   ghproxy.net  hub.gitmirror.com  ghproxy.cc  gh.llkk.cc  ghp.ci  gh.7fa.cn
#   gh.xxooo.cf  cf.ghproxy.cc  ghproxy.cfd  gh.6yit.com  github.moeyy.xyz
#   gh.jasonzeng.dev  gitproxy.mrhjx.cn  ghproxy.imciel.com  gh.zzj.cool
#   api.kkgithub.com  gh.494888.xyz  gh-proxy.top  ghp.arislee.com
#   ghproxy.1888866.xyz(525)  gh.xiu.workers.dev
