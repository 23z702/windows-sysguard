"""unload_driver.py —— 向驱动发送卸载令牌

驱动默认不注册 DriverUnload，因此内核直接拒绝卸载（sc stop 报 1052）。
这是「拒绝停止」唯一可靠的实现方式：DriverUnload 是 VOID，没有拒绝通道。

要卸载必须先发令牌，驱动收到后才会把卸载例程装回去：
    python user/unload_driver.py
    sc stop sysguard
    sc delete sysguard
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import guard_ctl
import elevate


def main():
    try:
        g = guard_ctl.Guard()
    except OSError as e:
        print(f"驱动设备打不开，可能本来就没加载：{e}")
        return 0
    g.unload_token()
    g.close()
    print("卸载令牌已下发，现在可以 sc stop sysguard")
    return 0


if __name__ == "__main__":
    # 卸载令牌走设备 IOCTL，设备只授权给管理员
    _rc = elevate.ensure_admin()
    if _rc is not None:
        sys.exit(_rc)
    sys.exit(elevate.finish(main()))
