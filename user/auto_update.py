"""auto_update.py —— 自动更新：从 GitHub Release 下载并就地换掉正在运行的驱动

为什么要自己写而不是「下载个安装包双击」：
    驱动是被 SCM 映射在系统里的，直接覆盖会报「文件被占用」；而本项目驱动默认还带
    自锁（拒绝卸载）。所以必须按固定顺序：关自锁 → 下发卸载令牌 → 停服务 →
    覆盖镜像 → 起服务 → 验证 → 失败回滚。少一步就会留下「服务起不来」的状态。

一次更新的完整顺序（每一步失败都能退回去）：
    1. 取最新 Release，挑资产，核对 SHA256SUMS —— 这一步不动任何东西
    2. 快照：防护开关 + 保护名单（驱动重启后是内存态，不存就丢了）
    3. 备份当前 .sys 到 build\\backups\\
    4. 关自锁 → 卸载令牌 → 停服务（等到真的 STOPPED 才继续）
    5. 覆盖镜像（带重试：刚停的驱动偶尔还要几百毫秒才放开文件）
    6. 起服务 → 连设备 → 比对文件哈希 + 服务状态
    7. 任何一步失败：停 → 恢复备份 → 起服务 → 恢复开关，原样退回去
    8. 成功：恢复防护开关与保护名单

用法：
    python user\\auto_update.py --check            # 只看有没有新版
    python user\\auto_update.py --apply --dry-run  # 打印计划，不动手
    python user\\auto_update.py --apply            # 只更新驱动
    python user\\auto_update.py --apply --all      # 驱动 + 用户层 py/README/VERSION
    python user\\auto_update.py --rollback         # 回到上一次更新前的驱动
    python user\\auto_update.py --status           # 看当前装的是哪一版、备份在哪

退出码：0 成功/无更新，1 失败（已回滚），2 参数或环境问题
"""

import hashlib
import json
import os
import shutil
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import guard_ctl          # noqa: E402
import service_ctl        # noqa: E402
import update_check       # noqa: E402

try:
    import elevate
except ImportError:       # 允许在没有 elevate 的场合被 import（比如被 GUI 直接调用）
    elevate = None

REPO = update_check.REPO
API = "https://api.github.com"
UA = "sysguard-auto-update/1.0"

BUILD = os.path.join(ROOT, "build")
DOWNLOADS = os.path.join(BUILD, "downloads")
BACKUPS = os.path.join(BUILD, "backups")
STATE = os.path.join(DOWNLOADS, "update_state.json")


class UpdateFail(Exception):
    """更新失败（消息直接给用户看）。"""


# ---------------- 基础工具 ----------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _token():
    for k in ("GITHUB_TOKEN", "GH_TOKEN", "SYGUARD_GITHUB_TOKEN"):
        v = os.environ.get(k)
        if v and v.strip():
            return v.strip()
    return None


def _get(url, timeout=15, accept="application/vnd.github+json", binary=False):
    """返回 (status, data)。data 是 JSON 或 bytes。4xx 不抛异常。"""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
    tok = _token()
    if tok and "api.github.com" in url:
        req.add_header("Authorization", "Bearer " + tok)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (raw if binary else json.loads(raw.decode("utf-8")))
    except urllib.error.HTTPError as e:
        return e.code, None
    except urllib.error.URLError as e:
        raise UpdateFail("连不上 GitHub：%s" % getattr(e, "reason", e))
    except (TimeoutError, OSError) as e:
        raise UpdateFail("请求超时：%s" % e)


def _norm_release(d):
    return {
        "tag": d.get("tag_name", ""),
        "version": (d.get("tag_name") or "").lstrip("vV"),
        "name": d.get("name") or d.get("tag_name", ""),
        "notes": (d.get("body") or "").strip(),
        "url": d.get("html_url", ""),
        "published": (d.get("published_at") or "")[:10],
        "assets": [{
            "name": a.get("name", ""),
            "url": a.get("browser_download_url", ""),
            "size": a.get("size", 0),
        } for a in (d.get("assets") or [])],
    }


def release_info(timeout=15):
    """最新 Release 的完整信息（含资产）。"""
    st, data = _get("%s/repos/%s/releases/latest" % (API, REPO), timeout)
    if st == 200 and isinstance(data, dict) and data.get("tag_name"):
        return _norm_release(data)
    st2, arr = _get("%s/repos/%s/releases?per_page=1" % (API, REPO), timeout)
    if st2 == 200 and isinstance(arr, list) and arr:
        return _norm_release(arr[0])
    raise UpdateFail("取不到 Release（HTTP %s），仓库可能还没发版" % st)


def download(url, dest, timeout=120, label=""):
    """下载到 dest，带进度。dest 已存在且大小一致就直接复用。"""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    tmp = dest + ".part"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            total = int(r.headers.get("Content-Length") or 0)
            done = 0
            with open(tmp, "wb") as f:
                while True:
                    chunk = r.read(1 << 16)
                    if not chunk:
                        break
                    f.write(chunk)
                    done += len(chunk)
                    if total and sys.stdout.isatty():
                        sys.stdout.write("\r  下载 %-24s %5.1f%%"
                                         % (label or os.path.basename(dest),
                                            100.0 * done / total))
                        sys.stdout.flush()
        if total and sys.stdout.isatty():
            sys.stdout.write("\n")
    except urllib.error.HTTPError as e:
        raise UpdateFail("下载失败 HTTP %s：%s" % (e.code, url))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise UpdateFail("下载中断：%s" % e)

    got = os.path.getsize(tmp)
    if total and got != total:
        os.unlink(tmp)
        raise UpdateFail("下载不完整：%s / %s 字节" % (got, total))
    os.replace(tmp, dest)
    return dest


# ---------------- 服务 / 镜像 ----------------
def current_service():
    """当前活跃实例对应的服务名；识别不到就退回 sysguard。"""
    try:
        n = guard_ctl.detect_service_name()
    except Exception:
        n = None
    return n or "sysguard"


def resolve_image_path(svc=None):
    """服务注册的镜像路径 -> 可读写的本机路径。

    ImagePath 可能写成 \\SystemRoot\\System32\\drivers\\x.sys 或 \\??\\C:\\...，
    这里统一翻译成真实路径，否则 open() 会失败。
    """
    svc = svc or current_service()
    ks = service_ctl.key_state(svc) or {}
    ip = ks.get("ImagePath") or ""
    if not ip:
        raise UpdateFail("服务 %s 没有 ImagePath，装过吗？" % svc)

    p = str(ip).strip().replace('"', "")
    low = p.lower()
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    if low.startswith("\\systemroot\\"):
        p = os.path.join(sysroot, p[len("\\systemroot\\"):])
    elif low.startswith("\\??\\"):
        p = p[4:]
    elif low.startswith("system32\\"):
        p = os.path.join(sysroot, p)

    if not os.path.isabs(p):
        raise UpdateFail("看不懂的 ImagePath：%r" % ip)
    return os.path.normpath(p)


def stop_driver(svc, wait=20):
    """关自锁 -> 卸载令牌 -> 停服务，并等到真的 STOPPED。"""
    try:
        with guard_ctl.Guard() as g:
            g.set_config(unload_lock=False)     # 自锁开着的话，令牌也会被忽略
            g.unload_token()
            print("  已下发卸载令牌（自锁已临时关闭）")
    except OSError as e:
        print("  设备打不开（可能已停）：%s" % e)
    time.sleep(0.4)

    service_ctl.do_stop(svc)
    for _ in range(wait * 10):
        st = service_ctl.service_state(svc)
        if st is None or st == 1:               # 不存在 / STOPPED
            return True
        time.sleep(0.1)
    return False


def read_service_spec(svc=None):
    """把服务注册参数记下来。第三方安全软件会在驱动停下后顺手删掉服务键，
    没有这份记录就没法重建（实测踩过：停完 err=1060 服务不存在）。"""
    svc = svc or current_service()
    ks = service_ctl.key_state(svc) or {}
    return {
        "name": svc,
        "image_raw": ks.get("ImagePath"),
        "start": ks.get("Start"),
        "error_control": ks.get("ErrorControl"),
        "group": ks.get("Group"),
    }


def ensure_service(spec, image):
    """服务键不存在就按记录重建。返回 True 表示重建过。"""
    svc = spec.get("name") or current_service()
    if service_ctl.service_state(svc) is not None:
        return False

    print("  [!] 服务键已不存在（多半被安全软件清理了）→ 按更新前的记录重建")
    start = spec.get("start")
    if start not in (0, 1, 2, 3, 4):
        start = 2                              # 记录不到就按开机自启兜底
    if start in (0, 1):
        start = 2                              # boot/system 在运行中的系统上起不来
    if not service_ctl.do_create(svc, image, start):
        raise UpdateFail("服务键被删了，重建也失败（可能被安全软件拦住）")

    grp = spec.get("group")
    if grp:
        try:
            import winreg
            path = "SYSTEM" + chr(92) + "CurrentControlSet" + chr(92) + "Services" + chr(92) + svc
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "Group", 0, winreg.REG_SZ, grp)
            print("  已恢复 Group=%s" % grp)
        except OSError as e:
            print("  [i] 补 Group 失败（不影响本次启动）：%s" % e)
    return True


def start_driver(svc, spec=None, image=None, wait=15):
    if service_ctl.service_state(svc) is None and spec:
        ensure_service(spec, image or spec.get("image_raw") or "")
    service_ctl.do_start(svc)
    for _ in range(wait * 10):
        if service_ctl.service_state(svc) == 4:
            return True
        time.sleep(0.1)
    return False


def replace_image(image, new_sys, tries=12):
    """覆盖镜像。刚停的驱动要几百毫秒才放开文件，所以重试而不是一次失败就放弃。"""
    last = None
    for i in range(tries):
        try:
            shutil.copyfile(new_sys, image)
            return True
        except PermissionError as e:
            last = e
            time.sleep(0.5)
        except OSError as e:
            raise UpdateFail("写 %s 失败：%s" % (image, e))
    raise UpdateFail("目标文件一直被占用（重试 %d 次）：%s" % (tries, last))


# ---------------- 快照 / 状态 ----------------
def snapshot():
    """记录防护开关与保护名单 —— 驱动重启后这些是内存态，不存就没了。"""
    snap = {"config": None, "pids": [], "connected": False}
    try:
        with guard_ctl.Guard() as g:
            snap["config"] = g.query()["config"]
            snap["pids"] = g.list_pids()
            snap["connected"] = True
    except OSError as e:
        snap["error"] = str(e)
    return snap


def restore_snapshot(snap):
    if not snap or not snap.get("config"):
        return
    try:
        with guard_ctl.Guard() as g:
            g.set_config(**snap["config"])
            back = 0
            for pid in snap.get("pids") or []:
                try:
                    g.protect(pid)
                    back += 1
                except OSError:
                    pass                # 进程可能已经退出，忽略
        print("  已恢复防护开关与保护名单（%d 个进程）" % back)
    except OSError as e:
        print("  [!] 恢复配置失败：%s" % e)


def save_state(obj):
    os.makedirs(DOWNLOADS, exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE)


def load_state():
    try:
        with open(STATE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def backup_image(image, version):
    os.makedirs(BACKUPS, exist_ok=True)
    base = os.path.splitext(os.path.basename(image))[0]
    dst = os.path.join(BACKUPS, "%s-%s-%s.sys"
                       % (base, version or "unknown", time.strftime("%Y%m%d-%H%M%S")))
    shutil.copy2(image, dst)
    return dst


# ---------------- 更新主体 ----------------
def pick_driver_asset(rel):
    cands = [a for a in rel["assets"] if a["name"].lower().endswith(".sys")]
    if not cands:
        return None
    want = rel["version"]
    for a in cands:
        if want and want in a["name"]:
            return a
    return cands[0]


def expected_hash(rel, asset_name):
    """从 Release 里的 SHA256SUMS.txt 取期望值；取不到返回 None（仍会做基本校验）。"""
    sums = [a for a in rel["assets"] if a["name"].lower() == "sha256sums.txt"]
    if not sums:
        return None
    try:
        st, raw = _get(sums[0]["url"], timeout=20, binary=True)
        if st != 200 or not raw:
            return None
        for line in raw.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[-1].lstrip("*") == asset_name:
                return parts[0].lower()
    except (UpdateFail, OSError):
        return None
    return None


def install_driver(rel, dry=False):
    svc = current_service()
    image = resolve_image_path(svc)
    asset = pick_driver_asset(rel)
    if asset is None:
        raise UpdateFail("Release 里没有 .sys 资产（只有源码？），无法自动更新驱动")

    print("服务      : %s" % svc)
    print("镜像      : %s" % image)
    print("新版本    : %s" % rel["version"])
    print("资产      : %s (%.0f KB)" % (asset["name"], asset["size"] / 1024.0))

    spec = read_service_spec(svc)
    print("服务注册  : Start=%s ErrorControl=%s Group=%s"
          % (spec.get("start"), spec.get("error_control"), spec.get("group")))

    if not os.path.isfile(image):
        raise UpdateFail("当前镜像不存在：%s" % image)
    if dry:
        print("\n[dry-run] 将要：停服务 → 备份 → 覆盖镜像 → 起服务 → 校验 → 恢复配置")
        return {"dry": True}

    # 1) 下载 + 校验
    dest = os.path.join(DOWNLOADS, "v" + rel["version"], asset["name"])
    print("\n[1/6] 下载")
    download(asset["url"], dest, label=asset["name"])
    got = sha256_file(dest)
    want = expected_hash(rel, asset["name"])
    if want and got != want:
        os.unlink(dest)
        raise UpdateFail("校验失败：期望 %s…，实际 %s…" % (want[:16], got[:16]))
    if want:
        print("  sha256 校验通过：%s…" % got[:16])
    else:
        print("  [!] Release 里没有校验清单，跳过 sha256 比对（仅比对文件大小）")

    old_version = ""
    try:
        with guard_ctl.Guard() as g:
            old_version = g.query()["version"]
    except OSError:
        pass

    # 2) 快照
    print("[2/6] 记录当前状态")
    snap = snapshot()
    print("  防护开关 : %s" % (snap.get("config") or "未连接"))
    print("  保护名单 : %s" % (snap.get("pids") or []))

    # 3) 备份
    print("[3/6] 备份当前驱动")
    backup = backup_image(image, old_version)
    print("  -> %s" % backup)
    save_state({
        "when": time.strftime("%Y-%m-%d %H:%M:%S"),
        "service": svc, "image": image,
        "service_spec": spec,
        "from_version": old_version, "to_version": rel["version"],
        "backup": backup, "new_sha256": got,
        "snapshot": snap,
    })

    # 4) 停
    print("[4/6] 停止驱动")
    if not stop_driver(svc):
        raise UpdateFail("停不下来（自锁/令牌没生效？）。没动任何文件，请手动处理")

    # 5) 换
    failed = None
    try:
        print("[5/6] 覆盖镜像")
        replace_image(image, dest)
        print("  已写入 %s" % image)

        print("[6/6] 启动并校验")
        if not start_driver(svc, spec, image):
            raise UpdateFail("服务起不来（新驱动签名/依赖有问题）")
        if service_ctl.key_state(svc) is None:
            raise UpdateFail("服务键启动后又被删了（安全软件在拦），已回滚")
        now = sha256_file(image)
        if now != got:
            raise UpdateFail("镜像哈希对不上，写入可能被拦")
        with guard_ctl.Guard() as g:
            q = g.query()
        if not q.get("loaded"):
            raise UpdateFail("驱动没上报 loaded")
        print("  服务 RUNNING，设备可连，驱动版本 %s" % q["version"])
    except Exception as e:
        failed = e
        print("\n[!] 更新失败：%s" % e)
        print("[!] 开始回滚到备份")
        if stop_driver(svc):
            try:
                replace_image(image, backup)
                if start_driver(svc, spec, image):
                    print("  已回滚，服务恢复正常")
                    restore_snapshot(snap)
                else:
                    print("  [!!] 回滚后仍起不来，请手动检查：%s" % image)
            except UpdateFail as e2:
                print("  [!!] 回滚失败：%s" % e2)
        else:
            print("  [!!] 回滚时停不下来，请手动处理")
        raise (failed if isinstance(failed, UpdateFail) else UpdateFail(str(failed)))

    # 7) 恢复内存态
    restore_snapshot(snap)
    st = load_state() or {}
    st.update(ok=True, installed_at=time.strftime("%Y-%m-%d %H:%M:%S"))
    save_state(st)
    print("\n驱动已更新到 %s（旧版备份：%s）" % (rel["version"], backup))
    return {"ok": True, "version": rel["version"], "backup": backup}


def update_app_files(rel, dry=False):
    """更新用户层运行文件：user/*.py、README.md、VERSION。

    只碰「运行时会用到的文件」，不碰 build/ 下的脚本与任何本地配置；
    每个被覆盖的文件先备份到 build\\backups\\app-<时间>\\。
    """
    tag = rel["tag"]
    url = "https://github.com/%s/archive/refs/tags/%s.tar.gz" % (REPO, tag)
    dest = os.path.join(DOWNLOADS, "src-%s.tar.gz" % rel["version"])

    print("用户层源码: %s" % url)
    if dry:
        print("[dry-run] 将解包并把 user/*.py、README.md、VERSION 覆盖到项目目录")
        return

    if not (os.path.isfile(dest) and os.path.getsize(dest) > 1024):
        download(url, dest, label="%s.tar.gz" % tag)

    stamp = time.strftime("%Y%m%d-%H%M%S")
    backdir = os.path.join(BACKUPS, "app-" + stamp)
    tmp = tempfile.mkdtemp(prefix="sysguard-src-")
    copied, backed = [], 0

    try:
        with tarfile.open(dest, "r:gz") as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                parts = m.name.split("/", 1)
                if len(parts) != 2:
                    continue
                relp = parts[1]
                keep = (relp.startswith("user/") and relp.endswith(".py")) or \
                       relp in ("README.md", "VERSION")
                if not keep or "__pycache__" in relp:
                    continue
                src = tf.extractfile(m)
                if src is None:
                    continue
                data = src.read()
                target = os.path.join(ROOT, relp.replace("/", os.sep))

                if os.path.isfile(target):
                    with open(target, "rb") as f:
                        if f.read() == data:
                            continue          # 内容一样，不碰（保留原修改时间）
                    os.makedirs(backdir, exist_ok=True)
                    bak = os.path.join(backdir, relp.replace("/", os.sep))
                    os.makedirs(os.path.dirname(bak), exist_ok=True)
                    shutil.copy2(target, bak)
                    backed += 1
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as f:
                    f.write(data)
                copied.append(relp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("  覆盖 %d 个文件，备份 %d 个到 %s" % (len(copied), backed, backdir))
    for p in copied:
        print("    " + p)
    if copied:
        print("  提示：界面正在用的代码是内存里的旧版，重启界面后生效。")


def rollback():
    st = load_state()
    if not st or not st.get("backup"):
        raise UpdateFail("没有可用的更新记录（build\\downloads\\update_state.json）")
    image = st["image"]
    backup = st["backup"]
    svc = st.get("service") or current_service()

    if not os.path.isfile(backup):
        raise UpdateFail("备份文件不见了：%s" % backup)

    print("回滚目标：%s -> %s" % (st.get("to_version"), st.get("from_version") or "备份"))
    print("镜像    ：%s" % image)
    spec = st.get("service_spec") or {}
    spec.setdefault("name", svc)
    if not stop_driver(svc):
        raise UpdateFail("停不下来，回滚中止（没动文件）")
    replace_image(image, backup)
    if not start_driver(svc, spec, image):
        raise UpdateFail("回滚后服务起不来，镜像已换成备份，请手动检查")
    with guard_ctl.Guard() as g:
        v = g.query()["version"]
    restore_snapshot(st.get("snapshot"))
    st.update(rolled_back_at=time.strftime("%Y-%m-%d %H:%M:%S"), ok=False)
    save_state(st)
    print("已回滚，当前驱动版本 %s" % v)


# ---------------- 命令行 ----------------
def _print_status():
    svc = current_service()
    image = None
    try:
        image = resolve_image_path(svc)
    except UpdateFail as e:
        print("镜像      : %s" % e)
    st = load_state() or {}

    print("本地版本  : %s" % update_check.local_version())
    print("服务      : %s（状态 %s）"
          % (svc, service_ctl.STATE_NAME.get(service_ctl.service_state(svc), "未知")))
    if image:
        print("镜像      : %s" % image)
        if os.path.isfile(image):
            print("镜像哈希  : %s…" % sha256_file(image)[:16])
        else:
            print("镜像哈希  : (文件不存在)")
    try:
        with guard_ctl.Guard() as g:
            q = g.query()
        print("驱动版本  : %s（受保护 %d，累计拦截 %d）"
              % (q["version"], q["protected"], q["blocked"]))
    except OSError as e:
        print("驱动连接  : 失败 %s" % e)
    if st:
        print("上次更新  : %s  %s -> %s"
              % (st.get("when"), st.get("from_version") or "?", st.get("to_version")))
        print("备份文件  : %s" % st.get("backup"))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    do_check = "--check" in argv
    do_apply = "--apply" in argv
    do_rollback = "--rollback" in argv
    do_status = "--status" in argv
    dry = "--dry-run" in argv
    yes = "--yes" in argv or "-y" in argv
    with_app = "--all" in argv or "--with-app" in argv
    force = "--force" in argv

    if not any((do_check, do_apply, do_rollback, do_status)):
        print(__doc__)
        return 2

    if elevate is not None and not elevate.is_admin() and not dry:
        rc = elevate.ensure_admin()
        if rc is not None:
            return rc

    if do_status:
        _print_status()
        return 0

    if do_rollback:
        try:
            rollback()
            return 0
        except UpdateFail as e:
            print("[FAIL] %s" % e)
            return 1

    try:
        rel = release_info()
    except UpdateFail as e:
        print("[FAIL] %s" % e)
        return 1

    local = update_check.local_version()
    newer = update_check.parse_version(rel["tag"]) > update_check.parse_version(local)

    print("本地版本  : %s" % local)
    print("最新版本  : %s  (%s)" % (rel["version"], rel["published"] or "无发布日期"))
    print("结论      : %s" % ("有新版本" if newer else "已是最新"))

    if do_check:
        return 0
    if not newer and not force:
        print("无需更新（要强制重装同一版：--force）")
        return 0
    if not yes:
        print("\n这一步会【短暂停止并替换正在运行的驱动】。")
        try:
            ans = input("继续？[y/N] ").strip().lower()
        except EOFError:
            ans = ""
        if ans not in ("y", "yes"):
            print("已取消")
            return 2

    try:
        install_driver(rel, dry=dry)
        if with_app:
            update_app_files(rel, dry=dry)
    except UpdateFail as e:
        print("\n[FAIL] %s" % e)
        print("        可用 python user\\auto_update.py --status 查看当前状态")
        return 1
    except OSError as e:
        print("\n[FAIL] 系统调用失败：%s" % e)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
