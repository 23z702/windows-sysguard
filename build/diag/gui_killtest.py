"""gui_killtest.py —— 自动验收 GUI 的「结束同名进程」。

起 3 个唯一命名的靶子 -> 界面里填筛选词 -> 自动确认弹窗 -> 检查是否全灭。
弹窗被替换成立即确认，所以不会卡住。
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
import guard_ctl  # noqa: E402

NAME = "sgkguitarget"
EXE = os.path.join(ROOT, "build", "diag", NAME + ".exe")


def main():
    shutil.copy(sys.executable, EXE)
    procs = [subprocess.Popen([EXE, os.path.join(ROOT, "user", "target_stub.py")],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              creationflags=0x08000000) for _ in range(3)]
    time.sleep(1.6)
    alive = [p.pid for p in procs if p.poll() is None]
    print("靶子 PID :", alive)
    if len(alive) != 3:
        print("靶子没起够，结论不可信")
        return 2

    # 弹窗全部自动走“是”，但把关键文案打出来，方便确认走的是哪条分支
    def yes(title, msg=None, *a, **k):
        print(f"  [弹窗-确认] {title}: {(msg or '')[:60]}".replace("\n", " "))
        return True

    def info(title, msg=None, *a, **k):
        print(f"  [弹窗-提示] {title}: {(msg or '')[:60]}".replace("\n", " "))
        return "ok"

    H.messagebox.askyesno = yes
    H.messagebox.showinfo = info
    H.messagebox.showwarning = info
    H.messagebox.showerror = info

    app = H.App()
    app.geometry("1060x690")
    app.update_idletasks()
    app.show("proc")
    app.proc_filter.set(NAME)
    app.update()
    rows = app.proc_tree.get_children()
    print("界面命中 :", len(rows), "行 | 计数栏:", app.proc_count.cget("text"))

    print("--- 点「结束同名进程」 ---")
    app.kill_by_name()
    app.update()
    time.sleep(1.2)

    left = [p.pid for p in procs if p.poll() is None]
    print("剩余存活 :", left or "无")
    print("状态栏   :", app.pill.cget("text").strip())
    app.destroy()

    try:
        os.remove(EXE)
    except OSError:
        pass
    return 0 if not left else 1


if __name__ == "__main__":
    sys.exit(main())
