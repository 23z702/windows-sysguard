"""killtest.py —— 强杀测试套件：用各种手段尝试结束"受保护"进程，验证驱动拦截效果

用法：
    python killtest.py --pid 1234            # 测试指定进程
    python killtest.py --pid 1234 --protect  # 先把它加入保护名单再测
    python killtest.py --spawn               # 自动拉起一个受保护靶子进程再测

判定：
    [拦截]  = 防御生效（期望结果）
    [突破]  = 防御失效，进程被打死
    [跳过]  = 环境不支持该手段
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

try:
    from . import guard_ctl
    from . import elevate
except ImportError:  # 直接 python killtest.py 运行时
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import guard_ctl
    import elevate

# ---------- Win32 常量 ----------
PROCESS_TERMINATE = 0x0001
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_READ = 0x0010
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_TERMINATE = 0x0001
THREAD_SUSPEND_RESUME = 0x0002
THREAD_QUERY_INFORMATION = 0x0040
SYNCHRONIZE = 0x00100000

ERROR_ACCESS_DENIED = 5
WAIT_TIMEOUT = 258

SERVICE_STOPPED = 1
SERVICE_CONTROL_STOP = 1
SC_MANAGER_ALL_ACCESS = 0xF003F
SERVICE_ALL_ACCESS = 0xF01FF

# 被测服务名（可由 --service 覆盖）。换服务名安装时测试要跟着换，
# 否则 OpenService 失败会被当成"拦截"，属于假阳性。
SERVICE_NAME = "sysguard"

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
advapi = ctypes.WinDLL("advapi32", use_last_error=True)

k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.TerminateProcess.restype = wt.BOOL
k32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.OpenThread.restype = wt.HANDLE
k32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.TerminateThread.restype = wt.BOOL
k32.TerminateThread.argtypes = [wt.HANDLE, wt.DWORD]
k32.SuspendThread.restype = wt.DWORD
k32.SuspendThread.argtypes = [wt.HANDLE]
k32.ResumeThread.restype = wt.DWORD
k32.ResumeThread.argtypes = [wt.HANDLE]
k32.CreateRemoteThread.restype = wt.HANDLE
k32.CreateRemoteThread.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.LPVOID,
                                   wt.LPVOID, wt.DWORD, wt.LPVOID]
k32.WaitForSingleObject.restype = wt.DWORD
k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
k32.GetModuleHandleW.restype = wt.HMODULE
k32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [wt.HMODULE, ctypes.c_char_p]

# 服务控制相关的原型也必须声明：x64 下不声明 argtypes，HANDLE 会按 int 截断
advapi.OpenSCManagerW.restype = wt.HANDLE
advapi.OpenSCManagerW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, wt.DWORD]
advapi.OpenServiceW.restype = wt.HANDLE
advapi.OpenServiceW.argtypes = [wt.HANDLE, wt.LPCWSTR, wt.DWORD]
advapi.CloseServiceHandle.restype = wt.BOOL
advapi.CloseServiceHandle.argtypes = [wt.HANDLE]
advapi.ControlService.restype = wt.BOOL
advapi.ControlService.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p]
advapi.DeleteService.restype = wt.BOOL
advapi.DeleteService.argtypes = [wt.HANDLE]


# ---------- ntdll 原生结构 ----------
class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_ushort),
                ("MaximumLength", ctypes.c_ushort),
                ("Buffer", ctypes.c_void_p)]


class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_ulong),
                ("RootDirectory", wt.HANDLE),
                ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
                ("Attributes", ctypes.c_ulong),
                ("SecurityDescriptor", wt.LPVOID),
                ("SecurityQualityOfService", wt.LPVOID)]


class CLIENT_ID(ctypes.Structure):
    _fields_ = [("UniqueProcess", wt.HANDLE),
                ("UniqueThread", wt.HANDLE)]


ntdll.NtOpenProcess.restype = ctypes.c_long
ntdll.NtOpenProcess.argtypes = [ctypes.POINTER(wt.HANDLE),
                                wt.DWORD,
                                ctypes.POINTER(OBJECT_ATTRIBUTES),
                                ctypes.POINTER(CLIENT_ID)]
ntdll.NtTerminateProcess.restype = ctypes.c_long
ntdll.NtTerminateProcess.argtypes = [wt.HANDLE, ctypes.c_long]


# ---------- 工具 ----------
def enable_vt():
    try:
        h = k32.GetStdHandle(-11)
        mode = wt.DWORD()
        k32.GetConsoleMode(h, ctypes.byref(mode))
        k32.SetConsoleMode(h, mode.value | 0x0004)
    except Exception:
        pass


def alive(pid):
    """进程是否存活（受保护进程可能打不开 QUERY 权限，用 SYNCHRONIZE + 等待判断）"""
    h = k32.OpenProcess(SYNCHRONIZE, False, pid)
    if not h:
        # 连 SYNCHRONIZE 都拿不到，用 tasklist 兜底
        try:
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                                 capture_output=True, text=True, timeout=10).stdout
            return str(pid) in out
        except Exception:
            return True
    try:
        return k32.WaitForSingleObject(h, 0) == WAIT_TIMEOUT
    finally:
        k32.CloseHandle(h)


def caller_pid():
    return os.getpid()


class Result:
    def __init__(self, name, expected):
        self.name = name
        self.expected = expected      # "deny" 表示期望被拦截
        self.verdict = "skip"
        self.detail = ""

    def deny(self, detail):
        self.verdict, self.detail = "blocked", detail

    def breach(self, detail):
        self.verdict, self.detail = "breached", detail

    def skip(self, detail):
        self.verdict, self.detail = "skip", detail


# ---------- 各类强杀手段 ----------
def t_terminate_basic(pid, r):
    h = k32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h:
        r.deny(f"OpenProcess(PROCESS_TERMINATE) 失败，err={ctypes.get_last_error()}")
        return
    ok = k32.TerminateProcess(h, 1)
    err = ctypes.get_last_error()
    k32.CloseHandle(h)
    if ok:
        r.breach("TerminateProcess 成功")
    else:
        r.deny(f"TerminateProcess 失败，err={err}（ACCESS_DENIED={ERROR_ACCESS_DENIED}）")


def t_terminate_all_access(pid, r):
    h = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        err = ctypes.get_last_error()
        r.deny(f"OpenProcess(PROCESS_ALL_ACCESS) 失败，err={err}")
        return
    ok = k32.TerminateProcess(h, 1)
    k32.CloseHandle(h)
    if ok:
        r.breach("全权限句柄 TerminateProcess 成功")
    else:
        r.deny(f"拿到句柄但 TerminateProcess 失败，err={ctypes.get_last_error()}")


def t_nt_native(pid, r):
    """绕过 Win32 包装，直接调 NtOpenProcess/NtTerminateProcess"""
    h = wt.HANDLE()
    cid = CLIENT_ID(ctypes.c_void_p(pid), None)
    oa = OBJECT_ATTRIBUTES()
    oa.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)

    status = ntdll.NtOpenProcess(ctypes.byref(h), PROCESS_TERMINATE, ctypes.byref(oa), ctypes.byref(cid))
    if status < 0:
        r.deny(f"NtOpenProcess 返回 0x{status & 0xFFFFFFFF:08X}")
        return
    status = ntdll.NtTerminateProcess(h, 0)
    k32.CloseHandle(h)
    if status < 0:
        r.deny(f"NtTerminateProcess 返回 0x{status & 0xFFFFFFFF:08X}")
    else:
        r.breach("原生系统调用成功结束进程")


def t_thread_kill(pid, r):
    """遍历线程，OpenThread(THREAD_TERMINATE) + TerminateThread"""
    import ctypes as C

    TH32CS_SNAPTHREAD = 0x00000004

    class THREADENTRY32(C.Structure):
        _fields_ = [("dwSize", C.c_ulong), ("cntUsage", C.c_ulong),
                    ("th32ThreadID", C.c_ulong), ("th32OwnerProcessID", C.c_ulong),
                    ("tpBasePri", C.c_long), ("tpDeltaPri", C.c_long), ("dwFlags", C.c_ulong)]

    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k32.Thread32First.restype = wt.BOOL
    k32.Thread32Next.restype = wt.BOOL

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if not snap or snap == wt.HANDLE(-1).value:
        r.skip("无法创建线程快照")
        return

    te = THREADENTRY32()
    te.dwSize = C.sizeof(THREADENTRY32)
    tids = []
    ok = k32.Thread32First(snap, C.byref(te))
    while ok:
        if te.th32OwnerProcessID == pid:
            tids.append(te.th32ThreadID)
        ok = k32.Thread32Next(snap, C.byref(te))
    k32.CloseHandle(snap)

    if not tids:
        r.skip("没找到目标线程")
        return

    blocked, killed, last_err = 0, 0, 0
    for tid in tids:
        h = k32.OpenThread(THREAD_TERMINATE, False, tid)
        if not h:
            blocked += 1
            last_err = ctypes.get_last_error()
            continue
        if k32.TerminateThread(h, 1):
            killed += 1
        else:
            blocked += 1
            last_err = ctypes.get_last_error()
        k32.CloseHandle(h)

    if killed:
        r.breach(f"{killed}/{len(tids)} 个线程被强杀")
    else:
        r.deny(f"{len(tids)} 个线程全部打开失败，err={last_err}")


def t_thread_suspend(pid, r):
    """挂起全部线程（另一种"杀死应用"的手法）"""
    import ctypes as C
    TH32CS_SNAPTHREAD = 0x00000004

    class THREADENTRY32(C.Structure):
        _fields_ = [("dwSize", C.c_ulong), ("cntUsage", C.c_ulong),
                    ("th32ThreadID", C.c_ulong), ("th32OwnerProcessID", C.c_ulong),
                    ("tpBasePri", C.c_long), ("tpDeltaPri", C.c_long), ("dwFlags", C.c_ulong)]

    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    te = THREADENTRY32()
    te.dwSize = C.sizeof(THREADENTRY32)
    ok = k32.Thread32First(snap, C.byref(te))
    total = denied = suspended = 0
    last_err = 0
    while ok:
        if te.th32OwnerProcessID == pid:
            total += 1
            h = k32.OpenThread(THREAD_SUSPEND_RESUME, False, te.th32ThreadID)
            if not h:
                denied += 1
                last_err = ctypes.get_last_error()
            else:
                # 关键：Ob 回调把权限位清零后，句柄依然能打开（只是权限为 0）。
                # 所以必须真的调用 SuspendThread 才知道能不能挂起。
                prev = k32.SuspendThread(h)
                if prev == 0xFFFFFFFF:
                    denied += 1
                    last_err = ctypes.get_last_error()
                else:
                    suspended += 1
                    k32.ResumeThread(h)      # 立刻恢复，别把靶子冻住影响后续测试
                k32.CloseHandle(h)
        ok = k32.Thread32Next(snap, C.byref(te))
    k32.CloseHandle(snap)

    if total == 0:
        r.skip("没找到目标线程")
    elif suspended == 0:
        r.deny(f"{denied}/{total} 个线程挂起失败（句柄可开但无权挂起），err={last_err}")
    else:
        r.breach(f"{suspended}/{total} 个线程被成功挂起")


def t_remote_thread(pid, r):
    """注入式结束：OpenProcess(CREATE_THREAD|VM_*) + CreateRemoteThread(ExitProcess)"""
    access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
    h = k32.OpenProcess(access, False, pid)
    if not h:
        r.deny(f"OpenProcess(注入权限) 失败，err={ctypes.get_last_error()}")
        return
    kernel32 = k32.GetModuleHandleW("kernel32.dll")
    exit_process = k32.GetProcAddress(kernel32, b"ExitProcess")
    th = k32.CreateRemoteThread(h, None, 0, exit_process, ctypes.c_void_p(1), 0, None)
    err = ctypes.get_last_error()
    k32.CloseHandle(h)
    if th:
        k32.WaitForSingleObject(th, 3000)
        k32.CloseHandle(th)
        r.breach("远程线程注入成功")
    else:
        r.deny(f"CreateRemoteThread 失败，err={err}")


def t_dup_handle(pid, r):
    """DUP_HANDLE 只是句柄复制通道，本身不能结束进程。

    真正的杀伤力来自「源进程手里已有一个带 TERMINATE 的目标句柄」，
    而那条路已经被 Ob 回调在句柄生成时就掐断了，所以这里如实标注影响面。
    """
    h = k32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
    if not h:
        r.deny(f"OpenProcess(PROCESS_DUP_HANDLE) 失败，err={ctypes.get_last_error()}")
        return
    k32.CloseHandle(h)
    r.deny("可打开 DUP_HANDLE，但它只能复制目标已有的句柄，拿不到带 TERMINATE 的目标句柄")


class SERVICE_STATUS(ctypes.Structure):
    """ControlService 会向这个结构写入 7 个 DWORD，缓冲区给小了会写穿内存"""
    _fields_ = [("dwServiceType", wt.DWORD),
                ("dwCurrentState", wt.DWORD),
                ("dwControlsAccepted", wt.DWORD),
                ("dwWin32ExitCode", wt.DWORD),
                ("dwServiceSpecificExitCode", wt.DWORD),
                ("dwCheckPoint", wt.DWORD),
                ("dwWaitHint", wt.DWORD)]


def t_service_stop(_pid, r):
    """尝试停止驱动服务（等价 sc stop <SERVICE_NAME>）"""
    scm = advapi.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
    if not scm:
        r.skip(f"OpenSCManager 失败，err={ctypes.get_last_error()}")
        return
    svc = advapi.OpenServiceW(scm, SERVICE_NAME, SERVICE_ALL_ACCESS)
    if not svc:
        err = ctypes.get_last_error()
        advapi.CloseServiceHandle(scm)
        r.skip(f"OpenService 失败，err={err}（驱动可能未装成服务）")
        return
    status = SERVICE_STATUS()
    ok = advapi.ControlService(svc, SERVICE_CONTROL_STOP, ctypes.byref(status))
    err = ctypes.get_last_error()
    advapi.CloseServiceHandle(svc)
    advapi.CloseServiceHandle(scm)

    if ok:
        # 停止请求被受理，检查驱动是否真的没了
        time.sleep(0.5)
        still = guard_ctl.is_installed()
        # 设备句柄还在说明拒绝卸载生效（DriverUnload 直接返回）
        if still:
            r.deny("停止请求被受理，但驱动拒绝卸载，设备仍在线")
        else:
            r.breach("驱动已被成功停止")
    else:
        r.deny(f"ControlService(STOP) 被拒绝，err={err}")


def detect_service_name():
    """当前活跃设备属于哪个服务（实现在 guard_ctl，测试与卸载脚本共用）"""
    return guard_ctl.detect_service_name()


def _service_image_path(name):
    import winreg

    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           rf"SYSTEM\CurrentControlSet\Services\{name}", 0, winreg.KEY_READ)
    except OSError:
        return "?"
    try:
        return winreg.QueryValueEx(k, "ImagePath")[0]
    except OSError:
        return "?"
    finally:
        winreg.CloseKey(k)


def _service_key_state(name):
    """读服务注册表键的真实状态。

    删除类测试一律用它裁决 —— DeleteService 的返回值不可信：SCM 会先在
    内存里把服务标记为删除、直接返回 TRUE，之后写注册表（DeleteFlag/Start）
    失败它也不改口。只有键上的实际内容能说明服务到底还在不在。
    """
    import winreg

    key = rf"SYSTEM\CurrentControlSet\Services\{name}"
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return {"exists": False}
    except OSError:
        return {"exists": True}
    try:
        st = {"exists": True}
        for v in ("DeleteFlag", "Start"):
            try:
                st[v] = winreg.QueryValueEx(k, v)[0]
            except FileNotFoundError:
                st[v] = None
        return st
    finally:
        winreg.CloseKey(k)


def _block_count():
    """读驱动累计拦截数，用来区分「系统本来就会拒」和「我们的回调拒绝」"""
    try:
        g = guard_ctl.Guard()
        try:
            return g.query().get("blocked", 0)
        finally:
            g.close()
    except Exception:
        return None


def t_service_delete(_pid, r):
    """尝试删除驱动服务（等价 sc delete <SERVICE_NAME>）"""
    scm = advapi.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
    if not scm:
        r.skip("OpenSCManager 失败")
        return
    svc = advapi.OpenServiceW(scm, SERVICE_NAME, 0x00010000)  # DELETE
    if not svc:
        advapi.CloseServiceHandle(scm)
        r.deny(f"OpenService(DELETE) 被拒绝，err={ctypes.get_last_error()}")
        return

    # 先看测试前的状态：如果这个键早就被标记删除（历史残留），这一项无法归因
    pre = _service_key_state(SERVICE_NAME)
    if not pre.get("exists"):
        advapi.CloseServiceHandle(svc)
        advapi.CloseServiceHandle(scm)
        r.skip("服务键不存在")
        return
    if pre.get("DeleteFlag") == 1 or pre.get("Start") == 4:
        advapi.CloseServiceHandle(svc)
        advapi.CloseServiceHandle(scm)
        r.skip(f"服务键测试前就已是 DeleteFlag={pre.get('DeleteFlag')}、Start={pre.get('Start')}"
               "（历史残留，无法归因）")
        return

    ok = advapi.DeleteService(svc)
    err = ctypes.get_last_error()
    advapi.CloseServiceHandle(svc)
    advapi.CloseServiceHandle(scm)

    time.sleep(0.3)
    st = _service_key_state(SERVICE_NAME)
    if not st.get("exists"):
        r.breach("服务键已被删除（DeleteService 真正生效）")
        return
    if st.get("DeleteFlag") == 1 or st.get("Start") == 4:
        r.breach(f"服务已被标记删除（DeleteFlag={st.get('DeleteFlag')}, Start={st.get('Start')}），重启后失效")
        return

    how = "成功" if ok else "失败"
    r.deny(f"DeleteService 返回{how}（err={err}），但服务键完好"
           f"（DeleteFlag 未写入，Start={st.get('Start')}）")


def t_delete_registry_key(_pid, r):
    """改写服务 ImagePath / 删除服务注册表键（绕过 SCM 的破坏手法）"""
    import winreg

    key = rf"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}"

    # 先读原值，万一写成功要还原，别留下一个指向 notepad 的服务
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ)
        original = winreg.QueryValueEx(k, "ImagePath")[0]
        winreg.CloseKey(k)
    except OSError as e:
        r.skip(f"读服务键失败，err={e.winerror}")
        return

    # 1) 改写 ImagePath —— 这才是注册表回调的直接检验。
    #    只测「删键」会假阳性：键下有 Parameters 子键时系统本来就返回拒绝访问。
    wrote = False
    werr = 0
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.SetValueEx(k, "ImagePath", 0, winreg.REG_EXPAND_SZ,
                              r"\??\C:\Windows\notepad.exe")
            wrote = True
        except OSError as e:
            werr = e.winerror
        finally:
            winreg.CloseKey(k)
    except OSError as e:
        werr = e.winerror

    if wrote:
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, "ImagePath", 0, winreg.REG_EXPAND_SZ, original)
            winreg.CloseKey(k)
        except OSError:
            pass
        r.breach("可以改写服务 ImagePath（注册表回调未生效）")
        return

    # 2) 删键。单看 err=5 分不清是「我们的回调」还是「键下有子键时系统本来
    #    就拒」，所以用驱动拦截计数的增量来归因。
    before = _block_count()
    try:
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key)
        r.breach("服务注册表键被删除")
    except FileNotFoundError:
        r.deny(f"ImagePath 改写被拒（err={werr}），服务键已不存在")
    except OSError as e:
        after = _block_count()
        by_us = before is not None and after is not None and after > before
        tag = "注册表回调拦截" if by_us else "系统拒绝，非本驱动功劳"
        r.deny(f"ImagePath 改写被拒（err={werr}），删键也被拒（err={e.winerror}，{tag}）")


TESTS = [
    ("Win32 TerminateProcess", t_terminate_basic),
    ("全权限句柄强杀", t_terminate_all_access),
    ("原生 NtTerminateProcess", t_nt_native),
    ("线程级 TerminateThread", t_thread_kill),
    ("挂起全部线程", t_thread_suspend),
    ("远程线程注入 ExitProcess", t_remote_thread),
    ("句柄复制通道", t_dup_handle),
    ("停止驱动服务", t_service_stop),
    ("删除驱动服务", t_service_delete),
    ("删除服务注册表键", t_delete_registry_key),
]


def main():
    global SERVICE_NAME

    ap = argparse.ArgumentParser(description="sysguard 强杀测试")
    ap.add_argument("--pid", type=int, help="被测目标进程 PID")
    ap.add_argument("--protect", action="store_true", help="测试前把目标加入保护名单")
    ap.add_argument("--spawn", action="store_true", help="自动拉起 target_stub.py 作为靶子")
    ap.add_argument("--service", default=None,
                    help="驱动服务名（默认自动识别当前活跃设备所属的服务）")
    args = ap.parse_args()

    if args.service:
        SERVICE_NAME = args.service
        svc_src = "手动指定"
    else:
        detected = detect_service_name()
        SERVICE_NAME = detected or SERVICE_NAME
        svc_src = "自动识别" if detected else "未识别到，退回默认"

    enable_vt()
    GREEN, RED, YELLOW, CYAN, DIM, RESET = (
        "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[90m", "\033[0m")

    try:
        guard = guard_ctl.Guard()
    except OSError as e:
        print(f"{RED}[!] {e}{RESET}")
        print("    请先以管理员身份安装并启动驱动： powershell -File build\\install.ps1")
        return 2

    child = None
    pid = args.pid
    if args.spawn:
        stub = os.path.join(os.path.dirname(os.path.abspath(__file__)), "target_stub.py")
        child = subprocess.Popen([sys.executable, stub],
                                 stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        pid = child.pid
        time.sleep(1.5)
        args.protect = True
        print(f"{CYAN}[*] 已拉起靶子进程 target_stub.py，PID={pid}{RESET}")

    if not pid:
        print(f"{RED}[!] 请指定 --pid 或使用 --spawn{RESET}")
        return 2

    pids = guard.list_pids()
    if args.protect and pid not in pids:
        guard.protect(pid)
        pids = guard.list_pids()
        print(f"{CYAN}[*] 已将 PID {pid} 加入保护名单{RESET}")

    protected = pid in pids
    st = guard.query()

    print()
    print(f"  目标 PID      : {pid}")
    print(f"  保护状态      : {(GREEN + '已保护' + RESET) if protected else (YELLOW + '未保护（当前为对照组）' + RESET)}")
    _img = _service_image_path(SERVICE_NAME)
    print(f"  驱动版本      : {guard_ctl.version_label(st['version'], guard_ctl.build_tag(_img))}")
    print(f"  被测服务      : {SERVICE_NAME}（{svc_src}）")
    print(f"  服务镜像      : {_img}")
    print(f"  累计拦截次数  : {st['blocked']}")
    print()
    print("  " + "─" * 74)
    print(f"  {'#':<3}{'攻击手法':<30}{'结果':<10}说明")
    print("  " + "─" * 74)

    results = []
    for i, (name, fn) in enumerate(TESTS, 1):
        r = Result(name, "deny")
        was_alive = alive(pid)
        try:
            fn(pid, r)
        except Exception as e:
            r.skip(f"异常: {e}")

        now_alive = alive(pid)
        # 以进程实际存活情况做最终裁决：进程没了就是突破。
        # 注意不要反过来把「进程还活着」当成一切正常 —— 全部线程被挂起同样是突破，
        # 那种情况由各测试自己判定。
        if was_alive and not now_alive:
            r.breach(r.detail or "进程已消失")

        color = {"blocked": GREEN, "breached": RED, "skip": YELLOW}[r.verdict]
        label = {"blocked": "拦截", "breached": "突破", "skip": "跳过"}[r.verdict]
        print(f"  {i:<3}{name:<30}{color}{label:<10}{RESET}{r.detail}")
        results.append(r)

        if not now_alive:
            print(f"\n  {RED}[!] 目标已被终止，后续测试终止{RESET}")
            break

    blocked = sum(1 for r in results if r.verdict == "blocked")
    breached = sum(1 for r in results if r.verdict == "breached")
    skipped = sum(1 for r in results if r.verdict == "skip")

    print("  " + "─" * 74)
    print(f"  合计 {len(results)} 项：{GREEN}拦截 {blocked}{RESET} / {RED}突破 {breached}{RESET} / {YELLOW}跳过 {skipped}{RESET}")

    if breached == 0 and protected:
        print(f"\n  {GREEN}结论：所有强杀手段均被 sysguard.sys 拦截，自我保护成立。{RESET}")
    elif breached == 0 and not protected:
        print(f"\n  {YELLOW}结论：目标未受保护但攻击全失败 —— 请检查是否 PID 已失效。{RESET}")
    else:
        print(f"\n  {RED}结论：存在 {breached} 项绕过路径，需要加固。{RESET}")

    guard.close()
    if child:
        print(f"\n  {DIM}靶子进程 PID {pid} 仍在运行，Ctrl+C 前可用 taskkill 手动清理{RESET}")
    return 0 if breached == 0 else 1


if __name__ == "__main__":
    # 强杀测试要开进程/线程句柄，非管理员根本没法构造这些调用，
    # 结果会一堆"跳过"，看着像驱动没拦住。
    _rc = elevate.ensure_admin()
    if _rc is not None:
        sys.exit(_rc)
    sys.exit(elevate.finish(main()))
