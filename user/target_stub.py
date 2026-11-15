"""target_stub.py —— 强杀测试用的靶子进程

作用：一个干净的、持续输出心跳的目标进程。
先保护它，再用各种手段尝试结束，观察它是否还在打印心跳。

带 --lock-dacl 时先把自己的安全描述符改成「空 DACL」：
它自己都打不开自己，管理员用 OpenProcess(PROCESS_TERMINATE) 也只会拿到 5。
用来复现「任务管理器里杀不掉」的顽固进程，配合驱动级强制结束做对照。
"""

import ctypes
import datetime
import os
import sys
import time

if sys.stdout:
    sys.stdout.reconfigure(line_buffering=True)


def lock_dacl():
    """把当前进程的 DACL 换成空表：拒绝所有人（含管理员）打开。"""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetCurrentProcess.restype = ctypes.c_void_p

    acl = ctypes.create_string_buffer(64)          # 空 ACL 很小
    adv.InitializeAcl.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
    if not adv.InitializeAcl(acl, ctypes.sizeof(acl), 2):   # ACL_REVISION = 2
        return False, ctypes.get_last_error()

    adv.SetSecurityInfo.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                    ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_void_p]
    # 注意：SetSecurityInfo 返回的是 Win32 错误码，0 = 成功（不是 BOOL）
    rc = adv.SetSecurityInfo(k32.GetCurrentProcess(),
                             6,     # SE_KERNEL_OBJECT
                             4,     # DACL_SECURITY_INFORMATION
                             None, None, acl, None)
    return rc == 0, rc


pid = os.getpid()
print("=" * 52)
print(f"  sysguard 强杀测试靶子进程")
print(f"  PID = {pid}")
print("  保护方法: python -m user.killtest --pid %d --protect" % pid)
if "--lock-dacl" in sys.argv:
    ok, err = lock_dacl()
    print(f"  DACL 自锁: {'成功（现在谁都打不开）' if ok else f'失败 err={err}'}")
print("=" * 52)

i = 0
try:
    while True:
        i += 1
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] 心跳 #{i}  pid={pid}  我还活着")
        time.sleep(1)
except KeyboardInterrupt:
    print("\n手动退出")
