"""update_check.py —— 版本自检组件：单独连 GitHub 查最新版本

设计要点（刻意做成「独立」的）：
    · 只依赖标准库 urllib/json，不 import guard_ctl、不碰驱动、不需要管理员；
    · 不依赖 git、不依赖任何 MCP/连接器，纯 HTTPS 打 GitHub 公开 API；
    · 复制这一个文件到别的机器上照样能跑（域名、仓库名都写在常量里）；
    · 网络不通/限流/仓库没有 Release 时不抛异常给界面，而是返回 ok=False + 原因。

版本号的三个来源（不要混）：
    · VERSION 文件      仓库根，形如 1.5.0，**发布版本**，与 GitHub tag 对齐；
    · GUARD_VERSION     驱动里的行为/接口版本（1.5），接口改了才升；
    · 构建号 v7         镜像文件名后缀，重编译一次加一，仅用于区分本机文件。
    自检比较的是「发布版本」，其余两个只作为兜底/展示。

命令行：
    python user\\update_check.py                # 人读
    python user\\update_check.py --json         # 机读（GUI/脚本用）
    python user\\update_check.py --force        # 忽略 6 小时缓存
    python user\\update_check.py --quiet        # 只在有新版本时输出

退出码： 0 已是最新 / 10 有新版本 / 2 检查失败（网络、限流、解析）
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

# ---------------- 常量 ----------------
REPO = "23z702/windows-sysguard"
API = "https://api.github.com"
UA = "sysguard-update-check/1.0 (+https://github.com/%s)" % REPO
CACHE_TTL = 6 * 3600          # 未认证 API 限流 60 次/小时，界面每次启动都查会被打满
CACHE_DIR = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
                         "sysguard")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                       # user/ 的上一级 = 仓库根
VERSION_FILE = os.path.join(ROOT, "VERSION")
DRIVER_SRC = os.path.join(ROOT, "driver", "sysguard.c")


class UpdateError(Exception):
    """检查失败时抛出，消息直接可以给用户看。"""


# ---------------- 版本解析 ----------------
def parse_version(text):
    """'v1.5.0' / '1.5' / 'V1.6.0-beta.1' -> (1, 5, 0)，补齐到三段。

    只取「数字段」，预发布后缀（-beta）不参与比较：发版时只要 tag 打了就算新版。
    解析不出来返回 (0, 0, 0)，让比较退化成「不会误报有新版本」。
    """
    if not text:
        return (0, 0, 0)
    m = re.match(r"^[vV]?(\d+(?:\.\d+)*)", str(text).strip())
    if not m:
        return (0, 0, 0)
    parts = [int(x) for x in m.group(1).split(".")][:3]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def fmt_version(tup):
    return ".".join(str(x) for x in tup)


def local_version():
    """本机发布版本：优先 VERSION 文件，其次解析驱动源码里的 GUARD_VERSION。"""
    try:
        with open(VERSION_FILE, "r", encoding="utf-8") as f:
            txt = f.read().strip()
        if txt:
            return txt.lstrip("vV")
    except OSError:
        pass

    # 兜底：从 driver/sysguard.c 的 GUARD_VERSION 0x00010005 反推 1.5
    try:
        with open(DRIVER_SRC, "r", encoding="utf-8", errors="ignore") as f:
            m = re.search(r"#define\s+GUARD_VERSION\s+0x([0-9A-Fa-f]{8})", f.read())
        if m:
            v = int(m.group(1), 16)
            return "%d.%d" % ((v >> 16) & 0xFFFF, v & 0xFFFF)
    except OSError:
        pass
    return "0.0.0"


# ---------------- HTTP ----------------
def _token():
    """有 GITHUB_TOKEN/GH_TOKEN 就带上：限流从 60 次/小时提到 5000。"""
    for k in ("GITHUB_TOKEN", "GH_TOKEN", "SYGUARD_GITHUB_TOKEN"):
        v = os.environ.get(k)
        if v and v.strip():
            return v.strip()
    return None


def _api(path, timeout=8):
    """GET api.github.com，返回 (status, json_or_None)。

    4xx/5xx 不抛异常，交给调用方决定语义（404 表示「没有 Release」而不是错误）。
    """
    url = API + path
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    tok = _token()
    if tok:
        req.add_header("Authorization", "Bearer " + tok)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw.decode("utf-8")) if raw else None)
    except urllib.error.HTTPError as e:
        body = None
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            pass
        if e.code in (403, 429) and _is_ratelimit(e, body):
            raise UpdateError("GitHub API 限流（未认证每小时 60 次），"
                              "稍后再试或设置 GITHUB_TOKEN")
        return e.code, body
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        raise UpdateError("连不上 GitHub：%s（检查代理 / DNS / 防火墙）" % reason)
    except (TimeoutError, OSError) as e:
        raise UpdateError("请求超时或被中断：%s" % e)
    except json.JSONDecodeError:
        raise UpdateError("GitHub 返回的不是 JSON（可能被代理劫持或需要登录）")


def _is_ratelimit(err, body):
    if err.headers.get("X-RateLimit-Remaining") == "0":
        return True
    msg = (body or {}).get("message", "") if isinstance(body, dict) else ""
    return "rate limit" in msg.lower()


# ---------------- 取最新版本 ----------------
def fetch_latest(timeout=8):
    """按可靠性依次退化：最新 Release -> 最新 Release 列表 -> 最新 Tag。

    返回 dict：tag / name / url / notes / published / source
    """
    st, data = _api("/repos/%s/releases/latest" % REPO, timeout)
    if st == 200 and isinstance(data, dict) and data.get("tag_name"):
        return {
            "tag": data["tag_name"],
            "name": data.get("name") or data["tag_name"],
            "url": data.get("html_url", ""),
            "notes": (data.get("body") or "").strip(),
            "published": (data.get("published_at") or "")[:10],
            "source": "release",
        }

    # 仓库还没发过 Release：GitHub 的 /releases/latest 返回 404
    if st in (404, 403):
        st2, arr = _api("/repos/%s/releases?per_page=1" % REPO, timeout)
        if st2 == 200 and isinstance(arr, list) and arr:
            r = arr[0]
            return {
                "tag": r.get("tag_name", ""),
                "name": r.get("name") or r.get("tag_name", ""),
                "url": r.get("html_url", ""),
                "notes": (r.get("body") or "").strip(),
                "published": (r.get("published_at") or "")[:10],
                "source": "release-list",
            }

        st3, tags = _api("/repos/%s/tags?per_page=1" % REPO, timeout)
        if st3 == 200 and isinstance(tags, list) and tags:
            t = tags[0]
            return {
                "tag": t.get("name", ""),
                "name": t.get("name", ""),
                "url": "https://github.com/%s/releases/tag/%s" % (REPO, t.get("name", "")),
                "notes": "",
                "published": "",
                "source": "tag",
            }
        raise UpdateError("仓库 %s 还没有任何 Release 或 Tag" % REPO)

    if st == 403:
        raise UpdateError("GitHub 拒绝了请求（403），可能是限流或网络被拦")
    raise UpdateError("GitHub 返回 HTTP %s" % st)


# ---------------- 缓存 ----------------
def _cache_path():
    return os.path.join(CACHE_DIR, "update.json")


def _read_cache():
    try:
        with open(_cache_path(), "r", encoding="utf-8") as f:
            c = json.load(f)
        return c if isinstance(c, dict) else None
    except (OSError, ValueError):
        return None


def _write_cache(obj):
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        tmp = _cache_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        os.replace(tmp, _cache_path())
    except OSError:
        pass          # 缓存写不进去不影响结论


# ---------------- 对外主接口 ----------------
def check(force=False, timeout=8, use_cache=True):
    """查一次版本，永远返回 dict，不抛异常。

    键：ok / local / latest / update / source / url / notes / published /
        checked_at / cached / error
    """
    local = local_version()
    now = time.time()

    if use_cache and not force:
        c = _read_cache()
        if (c and c.get("repo") == REPO and c.get("ok")
                and now - float(c.get("checked_ts", 0)) < CACHE_TTL):
            c["cached"] = True
            c["local"] = local
            c["update"] = parse_version(c.get("latest")) > parse_version(local)
            return c

    res = {"ok": False, "local": local, "latest": "", "update": False,
           "source": "", "url": "", "notes": "", "published": "",
           "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
           "checked_ts": now, "cached": False, "repo": REPO, "error": ""}

    try:
        info = fetch_latest(timeout)
    except UpdateError as e:
        res["error"] = str(e)
        return res
    except Exception as e:                      # 兜底：任何意外都不该让界面崩
        res["error"] = "未知错误：%s" % e
        return res

    res.update(ok=True, latest=info["tag"], source=info["source"],
               url=info["url"], notes=info["notes"], published=info["published"])
    res["update"] = parse_version(info["tag"]) > parse_version(local)
    _write_cache(res)
    return res


def summary(res):
    """给界面用的一句话结论。"""
    if not res.get("ok"):
        return "检查失败：%s" % (res.get("error") or "未知原因")
    if res.get("update"):
        return "有新版本 %s（当前 %s）" % (res["latest"], res["local"])
    return "已是最新 %s" % res["local"]


# ---------------- 命令行 ----------------
def _print_human(res, verbose=True):
    if not verbose and not res.get("update"):
        return
    if not res.get("ok"):
        print("[!] %s" % summary(res))
        return

    print("sysguard 版本自检")
    print("  仓库     : https://github.com/%s" % REPO)
    print("  本机版本 : %s" % res["local"])
    print("  最新版本 : %s%s" % (res["latest"],
                                 "  (%s)" % res["source"] if res["source"] else ""))
    if res.get("published"):
        print("  发布时间 : %s" % res["published"])
    if res.get("cached"):
        print("  (结果来自缓存，加 --force 可强制刷新)")
    print("  结论     : %s" % summary(res))

    if res.get("update"):
        if res.get("url"):
            print("  下载页   : %s" % res["url"])
        if res.get("notes"):
            print("  更新说明 :")
            for line in res["notes"].splitlines()[:20]:
                print("    " + line)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    quiet = "--quiet" in argv
    force = "--force" in argv
    timeout = 8
    if "--timeout" in argv:
        try:
            timeout = float(argv[argv.index("--timeout") + 1])
        except (IndexError, ValueError):
            print("--timeout 需要一个秒数", file=sys.stderr)
            return 2

    res = check(force=force, timeout=timeout, use_cache=not force)

    if as_json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        _print_human(res, verbose=not quiet)

    if not res.get("ok"):
        return 2
    return 10 if res.get("update") else 0


if __name__ == "__main__":
    raise SystemExit(main())
