"""gui_shot.py —— 无交互截图 GUI，用于改完界面后自查布局。

用法：
    python build/diag/gui_shot.py [输出.bmp] [筛选词] [页面名]

不触发提权（SYSGUARD_NO_ELEVATE=1），即使驱动未加载也能起界面。
"""
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys

os.environ.setdefault("SYSGUARD_NO_ELEVATE", "1")
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "user"))

import huorong_gui as H  # noqa: E402

user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)


class BMIH(ctypes.Structure):
    _fields_ = [("biSize", wt.DWORD), ("biWidth", ctypes.c_long),
                ("biHeight", ctypes.c_long), ("biPlanes", wt.WORD),
                ("biBitCount", wt.WORD), ("biCompression", wt.DWORD),
                ("biSizeImage", wt.DWORD), ("biXPelsPerMeter", ctypes.c_long),
                ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", wt.DWORD),
                ("biClrImportant", wt.DWORD)]


def capture(hwnd, path):
    rect = wt.RECT()
    user32.GetClientRect(hwnd, ctypes.byref(rect))
    w, h = rect.right - rect.left, rect.bottom - rect.top
    if w <= 0 or h <= 0:
        raise RuntimeError("窗口尺寸异常 %dx%d" % (w, h))
    hdc = user32.GetDC(hwnd)
    mdc = gdi32.CreateCompatibleDC(hdc)
    bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
    gdi32.SelectObject(mdc, bmp)
    # 2 = PW_RENDERFULLCONTENT，能抓到被遮挡/未激活的窗口
    if not user32.PrintWindow(hwnd, mdc, 2):
        user32.PrintWindow(hwnd, mdc, 0)

    bi = BMIH()
    bi.biSize = ctypes.sizeof(BMIH)
    bi.biWidth = w
    bi.biHeight = -h            # 负数 = top-down
    bi.biPlanes = 1
    bi.biBitCount = 24
    bi.biCompression = 0
    stride = ((w * 24 + 31) // 32) * 4
    bi.biSizeImage = stride * h
    buf = ctypes.create_string_buffer(bi.biSizeImage)
    gdi32.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(bi), 0)

    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(mdc)
    user32.ReleaseDC(hwnd, hdc)

    ih = struct.pack("<IiiHHIIiiII", 40, w, -h, 1, 24, 0, bi.biSizeImage, 0, 0, 0, 0)
    with open(path, "wb") as f:
        f.write(b"BM" + struct.pack("<IHHI", 54 + bi.biSizeImage, 0, 0, 54) + ih + buf.raw)
    return w, h


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build", "diag", "gui.png")
    word = sys.argv[2] if len(sys.argv) > 2 else ""
    page = sys.argv[3] if len(sys.argv) > 3 else "proc"
    if out.lower().endswith(".png"):
        out = out[:-4] + ".bmp"

    app = H.App()
    app.geometry("1060x690")
    app.update_idletasks()
    print("请求页面:", page, "| 当前 active:", app.active)
    app.show(page)
    print("切换后 active:", app.active)
    if word:
        app.proc_filter.set(word)
    app.update()

    hwnd = user32.GetAncestor(app.winfo_id(), 2) or app.winfo_id()

    def shot():
        app.update()
        w, h = capture(hwnd, out)
        st = app.proc_count.cget("text") if hasattr(app, "proc_count") else "-"
        print("已保存 %s  %dx%d" % (out, w, h))
        print("计数栏文本:", st)
        print("可见行数  :", len(app.proc_tree.get_children()))
        app.destroy()

    app.after(700, shot)
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
