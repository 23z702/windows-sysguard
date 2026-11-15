"""retire_old.py —— 退役设备 \\\\.\\sysguard1 上的旧实例（v1.2）。

步骤刻意做成幂等且保守：
    1. 清空保护名单（v1.2 有「名单非空时卸载必崩」的缺陷，必须先清）
    2. 关闭驱动自锁、下发卸载令牌
    3. 停服务（由 service_ctl 完成，本脚本不直接调 SCM）

不加 --apply 只打印将要做什么。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "user"))

import guard_ctl  # noqa: E402

DEVICE = "\\\\.\\sysguard1"
SERVICE = "sysguard3"


def main():
    apply = "--apply" in sys.argv
    if not apply:
        print("[体检模式] 加 --apply 才动内核\n")

    try:
        g = guard_ctl.Guard(DEVICE)
    except OSError as e:
        print("打不开 %s：%s" % (DEVICE, e))
        print("（可能已经退役了，直接 service_ctl stop --service %s）" % SERVICE)
        return 1

    try:
        st = g.query()
        pids = g.list_pids()
        print("版本 %s | 名单 %d 个 | 自锁 %s"
              % (st["version"], len(pids),
                 "开" if st["config"]["unload_lock"] else "关"))
        if g.path != DEVICE:
            print("[!] 连到的是 %s，不是目标设备，已中止" % g.path)
            return 1

        if pids:
            print("\n待清空的保护名单:", pids)
            if apply:
                for pid in pids:
                    ok = g.unprotect(pid)
                    print("  解除 %d -> %s" % (pid, ok))
                left = g.list_pids()
                if left:
                    print("[!] 仍有残留:", left, "—— 不许继续卸载")
                    return 1
                print("  名单已空")
            else:
                print("  （体检模式：这一步不做的话，卸载会触发 v1.2 的 UAF 蓝屏）")
        else:
            print("\n名单本来就是空的")

        if st["config"]["unload_lock"]:
            print("\n关闭驱动自锁")
            if apply:
                g.set_config(unload_lock=False)
                print("  自锁:", "开" if g.query()["config"]["unload_lock"] else "关")

        print("\n下发卸载令牌")
        if apply:
            try:
                print("  ->", g.unload_token())
            except OSError as e:
                print("  [!] 令牌失败:", e)
    finally:
        g.close()

    if apply:
        print("\n下一步（本脚本不代劳）：")
        print("  python user\\service_ctl.py stop --service %s" % SERVICE)
        print("  python user\\service_ctl.py delete --service %s" % SERVICE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
