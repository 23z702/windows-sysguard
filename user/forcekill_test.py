"""forcekill_test.py —— 验证「驱动级强制结束进程」（需要驱动 1.3+）

四个用例，每个都给出用户态对照，说明驱动这条路到底强在哪：

  1 普通进程      用户态 TerminateProcess 能杀，驱动也能杀（作为对照）
  2 DACL 自锁     目标把自己的 DACL 清空 → 用户态 OpenProcess 直接 5，
                  驱动仍能拿到句柄并结束  ← 核心卖点
  3 保护名单      默认拒绝（0xC0000022）；--force 才成功，并自动摘除保护
  4 结束自己      拒绝（0xC000000D），否则这条 IRP 没人收尾

用法：
    python user\\forcekill_test.py
    python user\\forcekill_test.py --pid 1234     # 只杀一个指定进程，看单次结果
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import elevate                      # noqa: E402
import guard_ctl                    # noqa: E402

STUB = os.path.join(HERE, "target_stub.py")
CREATE_NO_WINDOW = 0x08000000

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
_k32.OpenProcess.restype = ctypes.c_void_p
_k32.TerminateProcess.argtypes = [ctypes.c_void_p, wt.UINT]
_k32.TerminateProcess.restype = wt.BOOL
_k32.CloseHandle.argtypes = [ctypes.c_void_p]
_k32.CloseHandle.restype = wt.BOOL
_k32.GetCurrentProcess.argtypes = []
_k32.GetCurrentProcess.restype = wt.HANDLE

_adv = ctypes.WinDLL("advapi32", use_last_error=True)

ERROR_NOT_ALL_ASSIGNED = 1300


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wt.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]


TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x0002

# 必须显式声明签名：GetCurrentProcess 返回的是伪句柄 -1，
# 不声明 argtypes 时 ctypes 按有符号 int 传参，直接 OverflowError。
_adv.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
_adv.OpenProcessToken.restype = wt.BOOL
_adv.LookupPrivilegeValueW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, ctypes.POINTER(LUID)]
_adv.LookupPrivilegeValueW.restype = wt.BOOL
_adv.AdjustTokenPrivileges.argtypes = [wt.HANDLE, wt.BOOL,
                                       ctypes.POINTER(TOKEN_PRIVILEGES), wt.DWORD,
                                       ctypes.POINTER(TOKEN_PRIVILEGES),
                                       ctypes.POINTER(wt.DWORD)]
_adv.AdjustTokenPrivileges.restype = wt.BOOL


def set_debug_privilege(enable):
    """开关当前进程的 SeDebugPrivilege，返回它的前一个状态。

    这一步是演示的关键：管理员进程只要带 SeDebug，OpenProcess 会走
    「特权放行」而不是 DACL 检查，空 DACL 也照开不误。任务管理器这类
    工具默认不带，所以才出现「管理员也杀不掉」。

    坑一：AdjustTokenPrivileges 返回 TRUE 时 GetLastError() 仍可能是
    ERROR_NOT_ALL_ASSIGNED(1300) —— 那只是「令牌里没有该特权」的提示，
    不代表调用失败。早先把它当失败，SeDebug 实际没关掉，OpenProcess
    一路被特权放行，DACL 自锁那一项就永远是假的失败。
    坑二：不声明 argtypes 时 GetCurrentProcess 的 -1 伪句柄会溢出。
    """
    tok = wt.HANDLE()
    if not _adv.OpenProcessToken(_k32.GetCurrentProcess(),
                                 TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                 ctypes.byref(tok)):
        return None

    luid = LUID()
    if not _adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
        _k32.CloseHandle(tok)
        return None

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED if enable else 0

    # 通过 PrevState 读回旧值，用来在演示结束后恢复现场
    prev = TOKEN_PRIVILEGES()
    size = wt.DWORD(0)
    ctypes.set_last_error(0)
    ok = _adv.AdjustTokenPrivileges(tok, False, ctypes.byref(tp),
                                    ctypes.sizeof(prev), ctypes.byref(prev),
                                    ctypes.byref(size))
    err = ctypes.get_last_error()
    _k32.CloseHandle(tok)
    if not ok or err not in (0, ERROR_NOT_ALL_ASSIGNED):
        return None
    old = prev.Privileges[0].Attributes if prev.PrivilegeCount else 0
    return bool(old & SE_PRIVILEGE_ENABLED)


def user_mode_kill(pid):
    """普通用户态路径：OpenProcess(PROCESS_TERMINATE) + TerminateProcess。"""
    h = _k32.OpenProcess(0x0001, False, pid)
    if not h:
        return False, ctypes.get_last_error()
    try:
        ok = _k32.TerminateProcess(ctypes.c_void_p(h), 1)
        return bool(ok), ctypes.get_last_error()
    finally:
        _k32.CloseHandle(ctypes.c_void_p(h))


def spawn_stub(*extra):
    return subprocess.Popen([sys.executable, STUB, *extra],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=CREATE_NO_WINDOW)


def wait_gone(proc, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return True
        time.sleep(0.1)
    return proc.poll() is not None


def cleanup(proc):
    if proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass
        proc.wait(timeout=5)


class Report:
    def __init__(self):
        self.rows = []

    def add(self, name, expect, actual_ok, detail):
        self.rows.append((name, expect, actual_ok, detail))
        print(f"  {'✔' if actual_ok else '✘'} {name:<14} {detail}")

    def summary(self):
        bad = [r for r in self.rows if not r[2]]
        print()
        print(f"  合计 {len(self.rows)} 项：通过 {len(self.rows) - len(bad)} / 失败 {len(bad)}")
        return not bad


def main():
    ap = argparse.ArgumentParser(description="验证驱动级强制结束进程")
    ap.add_argument("--pid", type=int, help="只结束这一个进程，打印单次结果")
    args = ap.parse_args()

    if not guard_ctl.is_installed():
        print("驱动没装上，先跑 build\\install.ps1")
        return 1

    with guard_ctl.Guard() as g:
        ver = g.query()["version"]
        print(f"驱动版本: {ver}   设备: {g.path}")
        if tuple(int(x) for x in ver.split(".")) < (1, 3):
            print("这个版本没有强制结束（需要 1.3+），请先升级驱动")
            return 1

        if args.pid:
            r = g.kill(args.pid)
            print(f"PID {r['pid']}: status=0x{r['status']:08X} {r['text']} "
                  f"确认退出={r['waited']}")
            return 0 if r["ok"] else 1

        rep = Report()
        print()
        print("  ──────────────────────────────────────────────────────────")

        # ---- 1. 普通进程：两条路都能杀 ----
        p1 = spawn_stub()
        time.sleep(1.0)
        ok, err = user_mode_kill(p1.pid)
        rep.add("普通进程(用户态)", "成功", ok,
                f"TerminateProcess -> {ok}, err={err}")
        cleanup(p1)

        p2 = spawn_stub()
        time.sleep(1.0)
        r = g.kill(p2.pid)
        gone = wait_gone(p2)
        rep.add("普通进程(驱动)", "成功", r["ok"] and gone and r["waited"],
                f"status=0x{r['status']:08X} 已退出={gone} 内核确认={r['waited']}")
        cleanup(p2)

        # ---- 2. 目标自锁 DACL：用户态必然失败，驱动应该照杀 ----
        p3 = spawn_stub("--lock-dacl")
        time.sleep(1.5)
        prev = set_debug_privilege(False)     # 模拟任务管理器：不带 SeDebug
        try:
            ok, err = user_mode_kill(p3.pid)
            rep.add("DACL 自锁(用户态)", "失败", (not ok) and err == 5,
                    f"OpenProcess -> {'成功' if ok else f'失败 err={err}'}"
                    f"（SeDebug 已关={prev is not None}；带 SeDebug 会被特权放行）")
        finally:
            if prev is not None:
                set_debug_privilege(prev)

        alive_before = p3.poll() is None
        r = g.kill(p3.pid)
        gone = wait_gone(p3)
        # 0xC000010A = 进程已在退出中：说明上一步其实把它杀掉了，
        # 那样驱动这条路就没被真正验证到，判失败而不是放过。
        rep.add("DACL 自锁(驱动)", "成功", r["ok"] and gone and alive_before,
                f"status=0x{r['status']:08X} {r['text']} 杀前存活={alive_before} 已退出={gone}")
        cleanup(p3)

        # ---- 3. 保护名单：默认拒绝，--force 才动 ----
        p4 = spawn_stub()
        time.sleep(1.0)
        g.protect(p4.pid)
        r = g.kill(p4.pid)
        still = p4.poll() is None
        rep.add("保护目标(默认)", "拒绝",
                (not r["ok"]) and r["status"] == 0xC0000022 and still,
                f"status=0x{r['status']:08X} 仍存活={still}（预期被自我保护拦住）")

        r2 = g.kill(p4.pid, force=True)
        gone = wait_gone(p4)
        left = p4.pid in g.list_pids()
        rep.add("保护目标(--force)", "成功",
                r2["ok"] and gone and (not left) and bool(r2["method"] & 2),
                f"status=0x{r2['status']:08X} 已退出={gone} 名单已清除={not left}")
        cleanup(p4)

        # ---- 4. 结束自己：必须拒绝 ----
        r = g.kill(os.getpid())
        rep.add("结束调用者自身", "拒绝", r["status"] == 0xC000000D,
                f"status=0x{r['status']:08X} {r['text']}")

        print("  ──────────────────────────────────────────────────────────")
        ok = rep.summary()
        st = g.query()
        print(f"  驱动计数：核心拦截 {st['blocked']} / 静默 {st['quiet']} / "
              f"保护名单 {st['protected']}")
        print()
        print("  结论：驱动走内核句柄，目标 DACL 不参与判定；"
              "保护名单内需 --force，PPL 进程会明确失败。")
        return 0 if ok else 1


if __name__ == "__main__":
    rc = elevate.ensure_admin()
    if rc is not None:
        raise SystemExit(rc)
    sys.exit(elevate.finish(main()))
