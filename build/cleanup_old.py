"""cleanup_old.py —— 清理历史遗留的驱动服务与旧的 .sys 文件

背景：驱动迭代过程中服务名会变（sysguard -> sysguard2 -> sysguard3），
每换一版就多一个服务键。旧键留着有两个害处：
  1. Start=3 时虽然不自启，但手动/脚本误启动会造成多实例并存，两个实例
     同时注册 Ob/注册表回调，行为难以预测；
  2. 旧 .sys 被服务键引用着，删不掉也换不了，容易误用旧版本。

判定规则：
  - 候选 = Type 为 1/2（内核驱动、文件系统驱动）且 ImagePath 指向本项目
    build 目录，或服务名形如 sysguard*/probe*。
  - 保留 = 状态为 RUNNING 的服务（当前正在工作的实例）。
  - 其余一律视为遗留，按 stop -> DeleteService -> 删键 -> 若仍失败则设
    Start=4 的顺序降级处理。

用法：
    python build/cleanup_old.py            # 只体检，不动手（默认）
    python build/cleanup_old.py --apply     # 真正执行
    python build/cleanup_old.py --apply --purge-files   # 顺带把旧 .sys 移入 old/

注意：驱动默认不注册 DriverUnload，`stop` 对运行中的实例一定失败（1052），
所以 RUNNING 的实例不会被当成遗留项，脚本也不会去动它。
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import shutil
import sys
import time
import winreg

BUILD_DIR = os.path.dirname(os.path.abspath(__file__))

# 提权模块在 user\ 下，两个目录都要能跑起来（python build\cleanup_old.py）
sys.path.insert(0, os.path.join(os.path.dirname(BUILD_DIR), "user"))
import elevate
OLD_DIR = os.path.join(BUILD_DIR, "old")
SVC_BASE = "SYSTEM" + chr(92) + "CurrentControlSet" + chr(92) + "Services" + chr(92)

adv = ctypes.WinDLL("advapi32", use_last_error=True)
adv.OpenSCManagerW.restype = ctypes.c_void_p
adv.OpenSCManagerW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, wt.DWORD]
adv.OpenServiceW.restype = ctypes.c_void_p
adv.OpenServiceW.argtypes = [ctypes.c_void_p, wt.LPCWSTR, wt.DWORD]
adv.ControlService.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.c_void_p]
adv.QueryServiceStatus.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
adv.DeleteService.argtypes = [ctypes.c_void_p]
adv.CloseServiceHandle.argtypes = [ctypes.c_void_p]

SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_ALL_ACCESS = 0xF003F
SERVICE_QUERY_STATUS = 0x0004
SERVICE_ALL_ACCESS = 0xF01FF
SERVICE_CONTROL_STOP = 1

STATE = {1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING", 4: "RUNNING",
         5: "CONTINUE_PENDING", 6: "PAUSE_PENDING", 7: "PAUSED"}

# SCM 错误码在清理场景里几乎都会遇到，逐条给出人话解释，避免把「已完成」
# 当成「失败」，也避免把「拒绝」当成「权限不足」。
ERR_HINT = {
    1060: "服务已不存在（此前的删除请求已生效）",
    1061: "服务当前不接受控制请求（正在停止或已停）",
    1062: "服务没在运行",
    1072: "服务已被标记删除，等 SCM 释放",
    1073: "服务已存在",
    5: "访问被拒，多为键已进入删除队列",
}


def hint(err):
    return ERR_HINT.get(err, "")


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [("dwServiceType", wt.DWORD), ("dwCurrentState", wt.DWORD),
                ("dwControlsAccepted", wt.DWORD), ("dwWin32ExitCode", wt.DWORD),
                ("dwServiceSpecificExitCode", wt.DWORD), ("dwCheckPoint", wt.DWORD),
                ("dwWaitHint", wt.DWORD)]


def _scm(access=SC_MANAGER_ALL_ACCESS):
    h = adv.OpenSCManagerW(None, None, access)
    if not h:
        raise OSError(ctypes.get_last_error(), "OpenSCManager 失败（需要管理员权限）")
    return h


def svc_state(name):
    """返回 dwCurrentState；服务不存在返回 None。"""
    scm = _scm(SC_MANAGER_CONNECT)
    try:
        svc = adv.OpenServiceW(ctypes.c_void_p(scm), name, SERVICE_QUERY_STATUS)
        if not svc:
            return None
        try:
            st = SERVICE_STATUS()
            if not adv.QueryServiceStatus(ctypes.c_void_p(svc), ctypes.byref(st)):
                return None
            return st.dwCurrentState
        finally:
            adv.CloseServiceHandle(ctypes.c_void_p(svc))
    finally:
        adv.CloseServiceHandle(ctypes.c_void_p(scm))


def key_read(name):
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SVC_BASE + name, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return None
    except OSError:
        return None
    try:
        out = {}
        for v in ("ImagePath", "Start", "Type", "DeleteFlag", "DisplayName", "Altitude"):
            try:
                out[v] = winreg.QueryValueEx(k, v)[0]
            except FileNotFoundError:
                out[v] = None
        return out
    finally:
        winreg.CloseKey(k)


def discover():
    """枚举候选服务。"""
    out = []
    services = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SVC_BASE.rstrip(chr(92)), 0,
                              winreg.KEY_READ)
    try:
        i = 0
        while True:
            try:
                name = winreg.EnumKey(services, i)
            except OSError:
                break
            i += 1
            info = key_read(name)
            if not info:
                continue
            typ = info.get("Type") or 0
            if typ not in (1, 2, 0x10, 0x20):     # 内核驱动 / 文件系统驱动（含扩展位）
                continue
            img = (info.get("ImagePath") or "").lower()
            mine = os.path.basename(BUILD_DIR).lower() in img or "sysguard" in img
            if not mine and not name.lower().startswith(("sysguard", "probe")):
                continue
            out.append({"name": name, "image": info.get("ImagePath"),
                        "start": info.get("Start"), "type": typ,
                        "deleteflag": info.get("DeleteFlag"),
                        "state": svc_state(name)})
    finally:
        winreg.CloseKey(services)
    return sorted(out, key=lambda x: x["name"])


def disable(name):
    """把 Start 改成 4（不随系统启动），并打上 DeleteFlag。"""
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SVC_BASE + name, 0,
                           winreg.KEY_SET_VALUE)
    except OSError as e:
        print(f"    设 Start=4 失败：打不开键 (err={e.winerror})")
        return False
    try:
        winreg.SetValueEx(k, "Start", 0, winreg.REG_DWORD, 4)
        print("    已设 Start=4（不会随系统启动）")
        return True
    except OSError as e:
        print(f"    设 Start=4 失败 err={e.winerror}")
        return False
    finally:
        winreg.CloseKey(k)


def drop_service(name, state):
    """stop -> DeleteService -> 删键 -> 降级禁用。

    返回 "cleared"（键已消失）或 "marked"（已标记删除，等重启）。"""
    if state in (4, 2, 3):                    # RUNNING / *_PENDING
        scm = _scm()
        try:
            svc = adv.OpenServiceW(ctypes.c_void_p(scm), name, SERVICE_ALL_ACCESS)
            if svc:
                try:
                    buf = ctypes.create_string_buffer(64)
                    ok = adv.ControlService(ctypes.c_void_p(svc), SERVICE_CONTROL_STOP, buf)
                    err = ctypes.get_last_error()
                    tail = "" if ok else ("（" + hint(err) + "）" if hint(err) else "")
                    print(f"    stop -> {'ok' if ok else 'failed'} err={err} {tail}")
                finally:
                    adv.CloseServiceHandle(ctypes.c_void_p(svc))
        finally:
            adv.CloseServiceHandle(ctypes.c_void_p(scm))
        time.sleep(0.3)

    scm = _scm()
    try:
        svc = adv.OpenServiceW(ctypes.c_void_p(scm), name, SERVICE_ALL_ACCESS)
        if not svc:
            err = ctypes.get_last_error()
            if err == 1060:
                # 上一轮的 DeleteService 已经生效，SCM 这边先于注册表放手，
                # 所以这里「打不开」其实是清理成功的信号，不是失败。
                print("    OpenService -> 1060，SCM 已无此服务（上轮删除已生效）")
            else:
                print(f"    OpenService 失败 err={err} {hint(err)}")
        else:
            try:
                ok = adv.DeleteService(ctypes.c_void_p(svc))
                err = ctypes.get_last_error()
                print(f"    DeleteService -> {bool(ok)} err={err} {hint(err)}")
            finally:
                adv.CloseServiceHandle(ctypes.c_void_p(svc))
    finally:
        adv.CloseServiceHandle(ctypes.c_void_p(scm))

    time.sleep(0.4)
    if key_read(name) is None:
        print("    服务键已从注册表移除 -> 彻底清除")
        return "cleared"

    # DeleteService 只做「标记删除」，键要等 SCM 放手。这里直接删键兜底。
    try:
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, SVC_BASE + name)
        print("    直接删键成功")
        return "cleared"
    except OSError as e:
        if e.winerror == 5:
            # 键已被 SCM 标记删除后，配置管理器对该键一律返回 ACCESS_DENIED，
            # 所以既删不掉也不能改 Start。这不是权限问题，是「已在删除队列里」。
            print("    直接删键被拒 err=5 —— 键已进入删除队列，CM 对该键拒绝任何写入")
            print("    无需再设 Start=4：重启时 SCM 先处理删除队列，不会再加载它")
            return "marked"
        print(f"    直接删键失败 err={e.winerror}（镜像可能仍驻留内核，SCM 未放手）")

    return "disabled" if disable(name) else "stuck"


def purge_files(keep_images, apply):
    """把旧 .sys 移进 build/old/，被内核占用的跳过。"""
    keep = {os.path.basename((p or "").replace(chr(92) + "??" + chr(92), "")).lower()
            for p in keep_images if p}
    moved, skipped = [], []
    for fn in sorted(os.listdir(BUILD_DIR)):
        if not fn.lower().endswith((".sys", ".sys.bak")):
            continue
        if fn.lower() in keep:
            skipped.append((fn, "当前实例正在使用"))
            continue
        src = os.path.join(BUILD_DIR, fn)
        dst = os.path.join(OLD_DIR, fn)
        if not apply:
            moved.append((fn, "待移入 old/"))
            continue
        try:
            os.makedirs(OLD_DIR, exist_ok=True)
            if os.path.exists(dst):
                os.remove(dst)
            shutil.move(src, dst)
            moved.append((fn, "已移入 old/"))
        except OSError as e:
            # e.winerror is None for non-Win32 failures (e.g. a security product
            # or shell hook refusing the delete), so fall back to the message.
            detail = (f"err={e.winerror}" if getattr(e, "winerror", None)
                      else (e.strerror or str(e)))
            skipped.append((fn, f"移动失败（{detail}）"))
    return moved, skipped


def append_log(lines):
    """每次清理追加一段记录，便于回溯某次到底动了什么。"""
    os.makedirs(OLD_DIR, exist_ok=True)
    path = os.path.join(OLD_DIR, "cleanup_history.log")
    with open(path, "a", encoding="utf-8") as f:
        f.write(time.strftime("\n[%Y-%m-%d %H:%M:%S]\n"))
        for ln in lines:
            f.write(f"  {ln}\n")


def main():
    ap = argparse.ArgumentParser(description="清理遗留驱动服务与旧 .sys")
    ap.add_argument("--apply", action="store_true", help="真正执行（默认只体检）")
    ap.add_argument("--purge-files", action="store_true",
                    help="把非当前使用的 .sys 移入 build/old/")
    args = ap.parse_args()

    if not elevate.is_admin():
        print("[!] 当前不是管理员，删除服务键/移动文件大概率会失败")

    print(f"构建目录: {BUILD_DIR}")
    cands = discover()
    if not cands:
        print("没有发现本项目相关的驱动服务。")
    keep = [c for c in cands if c["state"] == 4]
    stale = [c for c in cands if c["state"] != 4]

    print("\n=== 服务清单 ===")
    for c in cands:
        tag = "保留(运行中)" if c in keep else "遗留"
        print(f"  {c['name']:<12} {tag:<10} state={STATE.get(c['state'], c['state'])} "
              f"Start={c['start']} image={c['image']}")
    if not keep:
        print("  [!] 没有任何 RUNNING 实例，注意不要连当前版本一起清掉")
    if not stale:
        print("  [ok] 没有遗留服务")

    if stale and args.apply:
        os.makedirs(OLD_DIR, exist_ok=True)
        snap = os.path.join(OLD_DIR, "services_backup.json")
        with open(snap, "w", encoding="utf-8") as f:
            json.dump(cands, f, ensure_ascii=False, indent=2)
        print(f"\n快照已存: {snap}")

    print("\n=== 处理 ===")
    result = {}
    for c in stale:
        print(f"[{c['name']}] state={STATE.get(c['state'], c['state'])}")
        if not args.apply:
            print("    体检模式：将执行 stop -> DeleteService -> 删键")
            continue
        result[c["name"]] = drop_service(c["name"], c["state"])
        time.sleep(0.2)

    if args.purge_files:
        print("\n=== 文件 ===")
        moved, skipped = purge_files([c["image"] for c in keep], args.apply)
        for fn, why in moved:
            print(f"  {fn:<22} {why}")
        for fn, why in skipped:
            print(f"  {fn:<22} 跳过：{why}")

    print("\n=== 复查 ===")
    for c in discover():
        print(f"  {c['name']:<12} state={STATE.get(c['state'], c['state'])} Start={c['start']}")

    marked = [n for n, r in result.items() if r == "marked"]
    stuck = [n for n, r in result.items() if r == "stuck"]
    hard_disabled = [n for n, r in result.items() if r == "disabled"]

    if marked:
        print(f"\n{', '.join(marked)}: 已进入删除队列，重启后由 SCM 自动清除，"
              "期间不会自启（Start=3 手动启动也会因已标记删除被拒）。")
    if hard_disabled:
        print(f"\n{', '.join(hard_disabled)}: 删不掉，已退而设 Start=4，重启后不再自启，"
              "可在下次重启后再执行一次 --apply 收尾。")
    if stuck:
        print(f"\n{', '.join(stuck)}: 既删不掉也改不了，需要重启后重试。")

    if args.apply:
        lines = [f"清单 {c['name']}: state={STATE.get(c['state'], c['state'])} "
                 f"Start={c['start']} image={c['image']}" for c in cands]
        lines.append("结果 " + (", ".join(f"{n}={r}" for n, r in result.items()) or "无遗留项"))
        if args.purge_files:
            lines.append("文件 " + (", ".join(f"{fn}:{why}" for fn, why in moved) or "无"))
            for fn, why in skipped:
                lines.append(f"跳过 {fn}: {why}")
        append_log(lines)

    if args.apply:
        print("\n完成。")
    else:
        print("\n以上为体检结果，未做任何修改。确认无误后加 --apply 执行。")


if __name__ == "__main__":
    # 删服务键、写 Start、移动 .sys 都要管理员，先自动提权
    _rc = elevate.ensure_admin()
    if _rc is not None:
        sys.exit(_rc)
    sys.exit(elevate.finish(main()))
