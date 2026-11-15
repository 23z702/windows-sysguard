"""gui_guardrail.py —— 验证「结束同名」的两道护栏真的能拦住。

测试方式：把靶子的进程名临时塞进 CRITICAL_PROCS，让它命中「系统关键进程」
分支。第一轮在弹窗里点「否」，必须一个都不杀；第二轮点「是」，才允许执行。

这样既测到分支，又绝不可能碰到真实系统进程。
"""
import os
import shutil
import subprocess
import sys
import time

os.environ.setdefault("SYSGUARD_NO_ELEVATE", "1")
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "user"))

import huorong_gui as H  # noqa: E402

NAME = "sgkguardrail"
EXE = os.path.join(ROOT, "build", "diag", NAME + ".exe")


def main():
    shutil.copy(sys.executable, EXE)
    procs = [subprocess.Popen([EXE, os.path.join(ROOT, "user", "target_stub.py")],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              creationflags=0x08000000) for _ in range(2)]
    time.sleep(1.6)
    print("靶子:", [p.pid for p in procs])

    H.messagebox.showinfo = lambda t, m=None, *a, **k: print("  [提示]", t)
    H.messagebox.showwarning = H.messagebox.showinfo

    state = {"deny_critical": True}

    def ask(title, msg=None, *a, **k):
        print("  [确认]", title)
        if "关键进程" in title and state["deny_critical"]:
            return False        # 第一轮：在这里踩刹车
        return True

    H.messagebox.askyesno = ask

    app = H.App()
    app.geometry("1060x690")
    app.update_idletasks()
    app.show("proc")
    app.proc_filter.set(NAME)
    app.update()

    # 临时把靶子当成“系统关键进程”
    H.CRITICAL_PROCS.add(NAME + ".exe")

    print("--- 第一轮：应该在关键进程确认框处被拦下 ---")
    app.kill_by_name()
    app.update()
    time.sleep(1.0)
    alive = [p.pid for p in procs if p.poll() is None]
    ok1 = len(alive) == 2
    print("结果: 存活", alive, "->", "护栏生效" if ok1 else "!! 没拦住")
    print("状态栏:", app.pill.cget("text").strip())

    print()
    print("--- 第二轮：确认继续，应全部结束 ---")
    state["deny_critical"] = False
    app.kill_by_name()
    app.update()
    time.sleep(1.2)
    left = [p.pid for p in procs if p.poll() is None]
    ok2 = not left
    print("结果: 剩余", left or "无", "->", "执行成功" if ok2 else "!! 未能结束")
    print("状态栏:", app.pill.cget("text").strip())

    app.destroy()
    for p in procs:
        try:
            p.kill()
        except OSError:
            pass
    try:
        os.remove(EXE)
    except OSError:
        pass
    print()
    print("总判定:", "通过" if (ok1 and ok2) else "失败")
    return 0 if (ok1 and ok2) else 1


if __name__ == "__main__":
    sys.exit(main())
