"""smoke_gui.py - 无驱动环境下构建界面并遍历所有页面，捕获布局异常"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "user"))

import huorong_gui as hg  # noqa: E402


def main():
    app = hg.App()
    for _ in range(8):
        app.update_idletasks()
        app.update()

    for key in ("home", "guard", "proc", "log", "about", "home"):
        app.show(key)
        app.update_idletasks()
        app.update()

    # 走一遍按钮回调里不依赖驱动的那部分
    app.refresh_status()
    app.update()
    app.refresh_log()
    app.update()

    w, h = app.winfo_width(), app.winfo_height()
    print(f"GUI SMOKE OK  window={w}x{h}  driver_ok={app.driver_ok}")
    app.destroy()
    return 0


if __name__ == "__main__":
    sys.exit(main())
