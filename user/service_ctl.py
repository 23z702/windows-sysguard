"""service_ctl.py —— 驱动服务管理（不依赖 sc.exe）

用法：
    python user/service_ctl.py status
    python user/service_ctl.py start
    python user/service_ctl.py stop
    python user/service_ctl.py delete
    python user/service_ctl.py uninstall     # 令牌 -> stop -> delete
    python user/service_ctl.py create --service sysguard4 --image build\\sysguard_v4.sys

选项：
    --service NAME    手动指定服务名；默认用 ActiveDevice 反查，避免打错实例
    --image PATH      仅 create 用，.sys 的绝对路径

两个必须知道的点：
1. 驱动默认**不注册 DriverUnload**，所以 `stop` 一定返回 1052。必须先发卸载令牌
   （IOCTL_GUARD_UNLOAD），驱动才会把卸载例程装回去。`uninstall` 会自动按这个顺序走。
2. sc.exe 在部分环境下会被安全策略拦掉（本仓库的执行沙箱就拦），但 SCM 的 API 一直
   可用，所以创建/删除/启停全部走 advapi32。

退出码：0 = 成功，1 = 失败。create/start 失败时会额外打印一行 `ERR=<Win32 错误码>`，
供 install.ps1 判断是否该换一个服务名重试。
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import guard_ctl
import elevate

adv = ctypes.WinDLL("advapi32", use_last_error=True)
adv.OpenSCManagerW.restype = ctypes.c_void_p
adv.OpenSCManagerW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, wt.DWORD]
adv.OpenServiceW.restype = ctypes.c_void_p
adv.OpenServiceW.argtypes = [ctypes.c_void_p, wt.LPCWSTR, wt.DWORD]
adv.ControlService.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.c_void_p]
adv.DeleteService.argtypes = [ctypes.c_void_p]
adv.QueryServiceStatus.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
adv.CloseServiceHandle.argtypes = [ctypes.c_void_p]

SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_CREATE_SERVICE = 0x0002
SC_MANAGER_ALL_ACCESS = 0xF003F
SERVICE_QUERY_STATUS = 0x0004
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
SERVICE_ALL_ACCESS = 0xF01FF
SERVICE_CONTROL_STOP = 1

SERVICE_KERNEL_DRIVER = 0x00000001
SERVICE_DEMAND_START = 0x00000003
SERVICE_ERROR_NORMAL = 0x00000001

# 启动类型。开机自动加载只能用 auto：boot/system 阶段文件系统还没就绪，
# 驱动放在普通卷上必然加载失败；disabled 则是彻底关掉。
SERVICE_BOOT_START = 0
SERVICE_SYSTEM_START = 1
SERVICE_AUTO_START = 2
SERVICE_DISABLED = 4
SERVICE_NO_CHANGE = 0xFFFFFFFF
SERVICE_CHANGE_CONFIG = 0x0002

START_VALUE = {"boot": 0, "system": 1, "auto": 2, "demand": 3, "disabled": 4}
START_NAME = {v: k for k, v in START_VALUE.items()}

adv.CreateServiceW.restype = ctypes.c_void_p
adv.CreateServiceW.argtypes = [
    ctypes.c_void_p, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD,
    wt.LPCWSTR, wt.LPCWSTR, ctypes.c_void_p, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR]
adv.StartServiceW.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.c_void_p]
adv.StartServiceW.restype = wt.BOOL

adv.ChangeServiceConfigW.restype = wt.BOOL
adv.ChangeServiceConfigW.argtypes = [
    ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.DWORD,
    wt.LPCWSTR, wt.LPCWSTR, ctypes.c_void_p,
    wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR]

ERROR_HINT = {
    2: "找不到镜像文件（路径写错，或用了正斜杠）",
    5: "拒绝访问（没提权，或被安全软件拦了）",
    183: "名字已存在",
    577: "镜像签名校验失败",
    1052: "服务不接受该控制（驱动未注册卸载例程，属正常防护）",
    1072: "服务已被标记删除（旧实例还驻留内核），换个名字",
    1073: "服务名已存在",
}

STATE_NAME = {1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING", 4: "RUNNING"}


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [("dwServiceType", wt.DWORD), ("dwCurrentState", wt.DWORD),
                ("dwControlsAccepted", wt.DWORD), ("dwWin32ExitCode", wt.DWORD),
                ("dwServiceSpecificExitCode", wt.DWORD), ("dwCheckPoint", wt.DWORD),
                ("dwWaitHint", wt.DWORD)]


def _open_scm(access=SC_MANAGER_ALL_ACCESS):
    scm = adv.OpenSCManagerW(None, None, access)
    if not scm:
        raise OSError(ctypes.get_last_error(), "OpenSCManager 失败（需要管理员权限）")
    return scm


def _open_service(scm, name, access=SERVICE_ALL_ACCESS):
    svc = adv.OpenServiceW(ctypes.c_void_p(scm), name, access)
    return svc


def service_state(name):
    scm = _open_scm(SC_MANAGER_CONNECT)
    try:
        svc = _open_service(scm, name, SERVICE_QUERY_STATUS)
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


def key_state(name):
    import winreg

    base = "SYSTEM" + chr(92) + "CurrentControlSet" + chr(92) + "Services" + chr(92)
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base + name, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return None
    except OSError as e:
        return {"error": e.winerror}
    try:
        out = {}
        for v in ("ImagePath", "Start", "DeleteFlag", "ErrorControl", "Type", "Group"):
            try:
                out[v] = winreg.QueryValueEx(k, v)[0]
            except FileNotFoundError:
                out[v] = None
        return out
    finally:
        winreg.CloseKey(k)


def send_unload_token():
    try:
        g = guard_ctl.Guard()
    except OSError as e:
        print(f"  设备打不开（可能本来就没加载）：{e}")
        return False
    try:
        g.unload_token()
        print(f"  卸载令牌已发往 {g.path}")
        return True
    finally:
        g.close()


def _norm_image(path):
    """统一 ImagePath 形式：\\??\\C:\\x\\y.sys / C:/x/y.sys -> C:\\x\\y.sys (小写)。"""
    if not path:
        return ""
    p = str(path).replace("/", "\\").lower()
    for pre in ("\\??\\", "\\\\?\\"):
        if p.startswith(pre):
            p = p[len(pre):]
    return p


def _image_holders(image):
    """哪些服务正在加载同一个 .sys。同一路径不能加载两次，内核会报 err=2。"""
    import winreg

    want = _norm_image(image)
    if not want:
        return []
    base = "SYSTEM" + chr(92) + "CurrentControlSet" + chr(92) + "Services"
    out = []
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base, 0, winreg.KEY_READ)
    except OSError:
        return out
    try:
        i = 0
        while True:
            try:
                name = winreg.EnumKey(k, i)
            except OSError:
                break
            i += 1
            try:
                sk = winreg.OpenKey(k, name, 0, winreg.KEY_READ)
                try:
                    ip = winreg.QueryValueEx(sk, "ImagePath")[0]
                finally:
                    winreg.CloseKey(sk)
            except OSError:
                continue
            if _norm_image(ip) == want and service_state(name) == 4:
                out.append(name)
    finally:
        winreg.CloseKey(k)
    return out


def do_create(name, image, start=SERVICE_DEMAND_START):
    print(f"[create] {name}")
    # ImagePath 必须是反斜杠：写成 C:/... 时 StartService 会返回 2（找不到文件）。
    # 这里统一转一次，省得调用方踩坑。
    image = os.path.abspath(image.replace("/", "\\"))
    print(f"  image  : {image}")
    print(f"  start  : {START_NAME.get(start, start)}")
    if not os.path.isfile(image):
        print(f"  镜像不存在：{image}")
        print("  ERR=2")
        return False
    scm = _open_scm(SC_MANAGER_CREATE_SERVICE)
    try:
        svc = adv.CreateServiceW(ctypes.c_void_p(scm), name, name, SERVICE_ALL_ACCESS,
                                 SERVICE_KERNEL_DRIVER, start,
                                 SERVICE_ERROR_NORMAL, image,
                                 None, None, None, None, None)
        if not svc:
            err = ctypes.get_last_error()
            print(f"  CreateService 失败 err={err}（{ERROR_HINT.get(err, '未知')}）")
            print(f"  ERR={err}")
            return False
        adv.CloseServiceHandle(ctypes.c_void_p(svc))
        print(f"  已创建：Type=kernel / Start={START_NAME.get(start, start)}")
        return True
    finally:
        adv.CloseServiceHandle(ctypes.c_void_p(scm))


def do_set_start(name, start, image=None):
    """改启动类型；给了 image 就同时换镜像路径。

    驱动在跑的时候改不了：它自己的 CmRegisterCallbackEx 会拦住对
    \\SERVICES\\<name> 的写入，表现为 err=5。所以调用方要先停驱动
    （自锁开着还得先 set_config(unload_lock=False) + 卸载令牌）。
    """
    print(f"[set-start] {name} -> {START_NAME.get(start, start)}")
    if not name:
        print("  未能识别服务名，用 --service 指定")
        print("  ERR=87")
        return False

    scm = _open_scm()
    try:
        svc = _open_service(scm, name, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS)
        if not svc:
            err = ctypes.get_last_error()
            print(f"  打不开服务 err={err}（{ERROR_HINT.get(err, '未知')}）")
            print(f"  ERR={err}")
            return False
        try:
            ok = adv.ChangeServiceConfigW(
                ctypes.c_void_p(svc),
                SERVICE_NO_CHANGE, start, SERVICE_NO_CHANGE,
                image, None, None, None, None, None, None)
            if not ok:
                err = ctypes.get_last_error()
                print(f"  ChangeServiceConfig 失败 err={err}"
                      f"（{ERROR_HINT.get(err, '未知')}）")
                if err == 5:
                    print("  提示：驱动还在运行，它的注册表自保护拒绝改写服务键。")
                    print("        先停驱动：python user\\service_ctl.py stop --service "
                          + name)
                print(f"  ERR={err}")
                return False
        finally:
            adv.CloseServiceHandle(ctypes.c_void_p(svc))
    finally:
        adv.CloseServiceHandle(ctypes.c_void_p(scm))

    ks = key_state(name) or {}
    now = ks.get("Start")
    print(f"  现在：Start={now}（{START_NAME.get(now, '?')}）"
          f"  Image={ks.get('ImagePath')}")
    return True


def do_start(name):
    print(f"[start] {name}")
    scm = _open_scm()
    try:
        svc = _open_service(scm, name, SERVICE_START | SERVICE_QUERY_STATUS)
        if not svc:
            err = ctypes.get_last_error()
            print(f"  打不开服务 err={err}（{ERROR_HINT.get(err, '未知')}）")
            print(f"  ERR={err}")
            return False
        try:
            if not adv.StartServiceW(ctypes.c_void_p(svc), 0, None):
                err = ctypes.get_last_error()
                print(f"  StartService 失败 err={err}（{ERROR_HINT.get(err, '未知')}）")
                print(f"  ERR={err}")
                if err == 2:
                    # 最常见的原因不是路径写错，而是同一个 .sys 已经被别的服务加载：
                    # 内核不允许同一镜像文件被映射两次，报出来就是 2（找不到文件）。
                    ks = key_state(name) or {}
                    img = ks.get("ImagePath")
                    holders = [h for h in _image_holders(img) if h.lower() != name.lower()]
                    if holders:
                        print(f"  提示：{img} 已被 {', '.join(holders)} 加载。")
                        print("        同一个 .sys 文件不能加载两次，解决办法二选一：")
                        print("        1) 复制成另一个文件名再装（内容相同也可以）")
                        print(f"        2) 先卸掉旧实例："
                              f"python user\\service_ctl.py uninstall --service {holders[0]}")
                return False
            st = SERVICE_STATUS()
            for _ in range(30):
                if not adv.QueryServiceStatus(ctypes.c_void_p(svc), ctypes.byref(st)):
                    break
                if st.dwCurrentState == 4:          # RUNNING
                    print("  RUNNING")
                    return True
                time.sleep(0.1)
            print(f"  已下发启动，当前状态 "
                  f"{STATE_NAME.get(st.dwCurrentState, st.dwCurrentState)}")
            return True
        finally:
            adv.CloseServiceHandle(ctypes.c_void_p(svc))
    finally:
        adv.CloseServiceHandle(ctypes.c_void_p(scm))


def do_stop(name):
    print(f"[stop] {name}")
    send_unload_token()
    time.sleep(0.3)
    scm = _open_scm()
    try:
        svc = _open_service(scm, name)
        if not svc:
            err = ctypes.get_last_error()
            if err == 1060:                     # 服务不存在 = 已经没有了
                print("  服务不存在（已达成目标）")
                return True
            print(f"  服务不存在 err={err}")
            return False
        try:
            buf = ctypes.create_string_buffer(64)
            ok = adv.ControlService(ctypes.c_void_p(svc), SERVICE_CONTROL_STOP, buf)
            err = ctypes.get_last_error()
            st = SERVICE_STATUS.from_buffer_copy(buf.raw[:ctypes.sizeof(SERVICE_STATUS)])
            print(f"  STOP -> {'ok' if ok else 'failed'} err={err}"
                  f" state={STATE_NAME.get(st.dwCurrentState, st.dwCurrentState)}")
            return bool(ok)
        finally:
            adv.CloseServiceHandle(ctypes.c_void_p(svc))
    finally:
        adv.CloseServiceHandle(ctypes.c_void_p(scm))


def do_delete(name):
    print(f"[delete] {name}")
    scm = _open_scm()
    try:
        svc = _open_service(scm, name)
        if not svc:
            err = ctypes.get_last_error()
            if err == 1060:
                print("  服务不存在（已达成目标）")
                return True
            print(f"  服务不存在 err={err}")
            return False
        try:
            ok = adv.DeleteService(ctypes.c_void_p(svc))
            err = ctypes.get_last_error()
        finally:
            adv.CloseServiceHandle(ctypes.c_void_p(svc))
    finally:
        adv.CloseServiceHandle(ctypes.c_void_p(scm))

    time.sleep(0.4)
    ks = key_state(name)
    if ks is None:
        print("  服务键已删除")
        return True
    print(f"  DeleteService -> {bool(ok)} err={err}；键仍在 {ks}，"
          "说明处于「删除挂起」，重启后会被 SCM 清除")
    return False


def do_status(name):
    print(f"service      : {name}")
    ks = key_state(name)
    if ks is None:
        print("service key  : 不存在")
    elif "error" in ks:
        print(f"service key  : 读取失败 {ks['error']}")
    else:
        print(f"service key  : Start={ks.get('Start')} DeleteFlag={ks.get('DeleteFlag')}")
        print(f"image path   : {ks.get('ImagePath')}")
    st = service_state(name)
    print(f"service state: {STATE_NAME.get(st, st) if st else '不存在'}")
    try:
        g = guard_ctl.Guard()
    except OSError as e:
        print(f"driver device: 打不开（{e.strerror}）")
        return
    try:
        q = g.query()
        img = guard_ctl.service_image_path(name)
        label = guard_ctl.version_label(q["version"], guard_ctl.build_tag(img))
        print(f"driver device: {g.path}  版本 {label}")
        print(f"driver image : {img}")
        print(f"counters     : 核心拦截 {q['blocked']} / 静默裁剪 {q['quiet']} / 受保护 {q['protected']}")
    finally:
        g.close()


def main():
    ap = argparse.ArgumentParser(description="sysguard 驱动服务管理")
    ap.add_argument("action",
                    choices=["status", "start", "stop", "delete", "uninstall",
                             "create", "set-start"])
    ap.add_argument("--service", default=None,
                    help="服务名（默认按 ActiveDevice 自动识别）")
    ap.add_argument("--image", default=None,
                    help="create 用：.sys 的绝对路径；set-start 用：同时换镜像路径")
    ap.add_argument("--start-type", default=None, choices=list(START_VALUE),
                    help="create / set-start 用：boot|system|auto|demand|disabled")
    args = ap.parse_args()

    start = START_VALUE[args.start_type] if args.start_type else SERVICE_DEMAND_START

    if args.action == "create":
        if not args.service or not args.image:
            ap.error("create 需要 --service 和 --image")
        return 0 if do_create(args.service, args.image, start) else 1

    name = args.service or guard_ctl.detect_service_name()
    if args.action == "set-start":
        if not args.start_type:
            ap.error("set-start 需要 --start-type auto|demand|system|boot|disabled")
        return 0 if do_set_start(name, start, args.image) else 1

    if not name:
        name = "sysguard"
        print(f"[!] 未能从 ActiveDevice 识别服务，退回默认名 {name}")

    if args.action == "status":
        do_status(name)
        return 0
    if args.action == "start":
        return 0 if do_start(name) else 1
    if args.action == "stop":
        return 0 if do_stop(name) else 1
    if args.action == "delete":
        return 0 if do_delete(name) else 1

    ok_stop = do_stop(name)
    ok_del = do_delete(name)
    return 0 if (ok_stop and ok_del) else 1


if __name__ == "__main__":
    # 打开 SCM 要 SERVICE_ALL_ACCESS，非管理员必定失败；先自动提权
    _rc = elevate.ensure_admin()
    if _rc is not None:
        sys.exit(_rc)
    sys.exit(elevate.finish(main()))
