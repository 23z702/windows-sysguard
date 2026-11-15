"""elevate.py —— 统一的「自动提权到管理员」入口

需要访问驱动设备（\\\\.\\sysguard1）或注册表服务键的脚本，入口统一写成：

    import elevate
    rc = elevate.ensure_admin()       # 已经是管理员 -> None
    if rc is not None:                # 刚弹过 UAC，活儿交给新进程，本进程退出
        sys.exit(rc)

    ...
    sys.exit(elevate.finish(main()))   # 提权子进程结束时保持窗口

两条提权通道
------------
1. ShellExecuteExW("runas") —— 首选。用 ExW 而不是 ShellExecuteW，是因为能拿到
   hProcess，父进程可以 WaitForSingleObject 等子进程结束并回传真实退出码；
   ShellExecuteW 拿不到句柄，退出码只能丢。
2. PowerShell 的 Start-Process -Verb RunAs —— 兜底。某些环境（受限令牌、第三方
   安全软件挂钩、部分远程会话）会让 shell32 的提权入口直接返回 err=5，
   此时改用 PowerShell 走同一条 UAC 通道，再靠 -PassThru -Wait 取退出码。

子进程怎么知道自己是被提权拉起来的
----------------------------------
靠命令行里的隐藏标记 --sysguard-elevated。它必须放在脚本路径**之后**（放前面
python 会当成自己的选项报错），本模块 import 时就从 sys.argv 里摘掉，
argparse 永远看不到它。据此在程序结束前 pause，否则新窗口一闪而过、输出全丢。

安全边界
--------
- 已是管理员：什么都不做。
- 子进程仍不是管理员（UAC 被组策略拦掉）：直接继续运行，**绝不递归提权**，
  否则会变成反复弹框的死循环。
- 用户点了 UAC 的「否」：返回 None，脚本按提示用当前权限继续。
- 环境变量 SYSGUARD_NO_ELEVATE=1 可关闭自动提权，用来故意复现「没权限」的
  报错路径（比如验证 err=5 的文案）。
"""

import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys

FLAG = "--sysguard-elevated"
ENV_OFF = "SYSGUARD_NO_ELEVATE"
ENV_NO_PAUSE = "SYSGUARD_NO_PAUSE"

_SEE_MASK_NOCLOSEPROCESS = 0x00000040
_SEE_MASK_NOASYNC = 0x00000100
_SW_SHOWNORMAL = 1
_INFINITE = 0xFFFFFFFF
_ERROR_CANCELLED = 1223
_PS_SENTINEL = "__SYSGUARD_ELEVATE_LAUNCHED__"


class _SHELLEXECUTEINFOW(ctypes.Structure):
    """shellapi.h 里的 SHELLEXECUTEINFOW（x64 下 120 字节）。"""
    _fields_ = [
        ("cbSize", wt.DWORD),
        ("fMask", ctypes.c_size_t),          # ULONG_PTR
        ("hwnd", wt.HWND),
        ("lpVerb", wt.LPCWSTR),
        ("lpFile", wt.LPCWSTR),
        ("lpParameters", wt.LPCWSTR),
        ("lpDirectory", wt.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wt.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wt.LPCWSTR),
        ("hkeyClass", wt.HKEY),
        ("dwHotKey", wt.DWORD),
        ("hIcon", wt.HANDLE),
        ("hProcess", wt.HANDLE),
    ]


_shell32 = ctypes.WinDLL("shell32", use_last_error=True)
_shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_SHELLEXECUTEINFOW)]
_shell32.ShellExecuteExW.restype = wt.BOOL

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
_k32.WaitForSingleObject.restype = wt.DWORD
_k32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
_k32.GetExitCodeProcess.restype = wt.BOOL
_k32.CloseHandle.argtypes = [wt.HANDLE]
_k32.CloseHandle.restype = wt.BOOL


def is_admin():
    """当前进程是否已提升为管理员。"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _strip_flag():
    """把隐藏标记从 sys.argv 摘掉（只看 [1:]，argv[0] 是脚本名）。"""
    for i in range(1, len(sys.argv)):
        if sys.argv[i] == FLAG:
            del sys.argv[i]
            return True
    return False


# import 时即生效：必须早于 argparse 解析
ELEVATED_CHILD = _strip_flag()


# ---------------------------------------------------------------- 通道 1
def _spawn_shellexec(argv, wait=True):
    """ShellExecuteExW + runas。返回 (ok, 退出码或错误码)。"""
    sei = _SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(_SHELLEXECUTEINFOW)
    sei.fMask = _SEE_MASK_NOCLOSEPROCESS | _SEE_MASK_NOASYNC
    sei.lpVerb = "runas"
    sei.lpFile = sys.executable
    sei.lpParameters = subprocess.list2cmdline(argv)
    sei.lpDirectory = os.getcwd()      # 相对路径（build\ user\）照旧能解析
    sei.nShow = _SW_SHOWNORMAL

    if not _shell32.ShellExecuteExW(ctypes.byref(sei)):
        return False, ctypes.get_last_error()

    h = sei.hProcess
    if not h or not wait:
        if h:
            _k32.CloseHandle(h)
        return True, 0

    try:
        _k32.WaitForSingleObject(h, _INFINITE)
        code = wt.DWORD()
        _k32.GetExitCodeProcess(h, ctypes.byref(code))
        return True, int(code.value)
    finally:
        _k32.CloseHandle(h)


# ---------------------------------------------------------------- 通道 2
def _ps_quote(text):
    return "'" + str(text).replace("'", "''") + "'"


def _spawn_powershell(argv, wait=True):
    """Start-Process -Verb RunAs 兜底。返回 (是否启动成功, 退出码或错误信息)。"""
    # -ArgumentList 传单个字符串：PS 5.1 传数组时会直接用空格拼接，
    # 含空格的参数会被拆开。这里交给 list2cmdline 做一次 Windows 规则引用。
    argline = subprocess.list2cmdline(argv)
    wait_part = " -Wait" if wait else ""
    # 子进程的退出码可能是非 0（测试失败也走这条路），所以不能拿 PowerShell 的
    # 退出码当「启动是否成功」的判据。启动成功时先打一个哨兵字样到 stdout。
    script = (
        "$ErrorActionPreference='Stop';"
        "try {"
        "  $p = Start-Process -FilePath %s -ArgumentList %s -Verb RunAs -PassThru%s;"
        "  [Console]::Out.WriteLine('%s');"
        "  if ($p) { exit $p.ExitCode } else { exit 0 }"
        "} catch {"
        "  [Console]::Error.WriteLine($_.Exception.Message); exit 1"
        "}"
    ) % (_ps_quote(sys.executable), _ps_quote(argline), wait_part, _PS_SENTINEL)

    try:
        p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                            "-Command", script],
                           capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)

    if _PS_SENTINEL in (p.stdout or ""):
        return True, p.returncode            # 退出码即子进程退出码

    msg = (p.stderr or p.stdout or "").strip()
    if "canceled" in msg.lower() or "取消" in msg:
        return True, _ERROR_CANCELLED        # 用户点了「否」，不算通道故障
    return False, msg or f"exit {p.returncode}"


# ---------------------------------------------------------------- 对外接口
def ensure_admin(script=None, argv=None, wait=True, auto=True):
    """确保当前脚本以管理员身份运行。

    返回值：
      None   —— 本来就是管理员（或提权被关闭 / 用户取消），继续往下跑即可
      int    —— 已把活交给提权后的子进程，调用方应 sys.exit(该值)
    """
    if ELEVATED_CHILD or is_admin():
        return None

    if not auto or os.environ.get(ENV_OFF) == "1":
        _note(f"未提权，且自动提权已关闭（{ENV_OFF}=1），以当前权限继续。")
        return None

    script = os.path.abspath(script or sys.argv[0])
    if not os.path.isfile(script):
        _note(f"找不到脚本文件 {script}，无法提权重启。")
        return None

    extra = list(sys.argv[1:] if argv is None else argv)
    child_argv = [script, FLAG] + extra
    _note(f"需要管理员权限，正在请求 UAC 提权…（{os.path.basename(script)}）")

    ok, result = _spawn_shellexec(child_argv, wait=wait)
    if not ok:
        _note(f"shell32 提权入口不可用（err={result}），改用 PowerShell 通道…")
        ok, result = _spawn_powershell(child_argv, wait=wait)

    if not ok:
        _note(f"提权启动失败（{result}），以当前权限继续运行。")
        return None

    if result == _ERROR_CANCELLED:
        _note("你取消了 UAC 授权，以当前权限继续运行。")
        return None

    if not wait:
        return 0
    if result != 0:
        _note(f"提权后的进程退出码 {result}。")
    return result


def finish(code=0):
    """提权子进程收尾时调用：有控制台就停一下，别让窗口一闪而过。"""
    if ELEVATED_CHILD and _has_console() and os.environ.get(ENV_NO_PAUSE) != "1":
        try:
            input("\n按回车键关闭此窗口…")
        except (EOFError, OSError, KeyboardInterrupt):
            pass
    return code


def _has_console():
    try:
        return (sys.stdin is not None and sys.stdin.isatty()
                and sys.stdout is not None and sys.stdout.isatty())
    except (ValueError, OSError):
        return False


def _note(msg):
    print(f"[elevate] {msg}", file=sys.stderr)


if __name__ == "__main__":
    print(f"管理员      : {is_admin()}")
    print(f"提权子进程  : {ELEVATED_CHILD}")
    print(f"解释器      : {sys.executable}")
    print(f"工作目录    : {os.getcwd()}")
