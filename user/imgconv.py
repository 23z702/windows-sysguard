"""imgconv.py —— 用 Windows 自带的 GDI+ 把 JPEG/其它格式转成 PNG（零第三方依赖）

为什么需要它：
    GitHub 的头像 URL 不管你要什么，返回的都是 JPEG；而 tkinter 的 PhotoImage
    只认 PNG/GIF/PPM。项目又刻意不引入 Pillow（要有 Pillow 才能跑就没法绿色分发）。

做法：
    ctypes 调 gdiplus.dll 的 flat API（GdiplusStartup / GdipCreateBitmapFromFile /
    GdipSaveImageToFile），先把图片解成 Gdiplus::Bitmap，再按 PNG 编码器存盘。
    GDI+ 是 Windows 自带组件，不安装任何东西。

对外只有一个函数：
    to_png(src, dst) -> bool      成功 True；任何失败都返回 False，不抛异常
"""

import ctypes
import os
from ctypes import wintypes


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


class GdiplusStartupInput(ctypes.Structure):
    _fields_ = [("GdiplusVersion", ctypes.c_uint32),
                ("DebugEventCallback", ctypes.c_void_p),
                ("SuppressBackgroundThread", wintypes.BOOL),
                ("SuppressExternalCodecs", wintypes.BOOL)]


class ImageCodecInfo(ctypes.Structure):
    _fields_ = [("Clsid", GUID),
                ("FormatID", GUID),
                ("CodecName", ctypes.c_wchar_p),
                ("DllName", ctypes.c_wchar_p),
                ("FilenameExtension", ctypes.c_wchar_p),
                ("MimeType", ctypes.c_wchar_p),
                ("Flags", wintypes.DWORD),
                ("Version", wintypes.DWORD),
                ("SigCount", wintypes.DWORD),
                ("SigSize", wintypes.DWORD),
                ("SigPattern", ctypes.POINTER(ctypes.c_ubyte)),
                ("SigMask", ctypes.POINTER(ctypes.c_ubyte))]


_gdip = None
_token = ctypes.c_void_p()
_started = False


def _lib():
    """只初始化一次；多线程同时进来也不会重复 GdiplusStartup。"""
    global _gdip, _started
    if _gdip is not None:
        return _gdip

    gdip = ctypes.WinDLL("gdiplus.dll")
    gdip.GdiplusStartup.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                                    ctypes.POINTER(GdiplusStartupInput),
                                    ctypes.c_void_p]
    gdip.GdiplusStartup.restype = ctypes.c_int
    gdip.GdiplusShutdown.argtypes = [ctypes.c_void_p]
    gdip.GdipCreateBitmapFromFile.argtypes = [ctypes.c_wchar_p,
                                              ctypes.POINTER(ctypes.c_void_p)]
    gdip.GdipCreateBitmapFromFile.restype = ctypes.c_int
    gdip.GdipDisposeImage.argtypes = [ctypes.c_void_p]
    gdip.GdipSaveImageToFile.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                         ctypes.POINTER(GUID), ctypes.c_void_p]
    gdip.GdipSaveImageToFile.restype = ctypes.c_int
    gdip.GdipGetImageEncodersSize.argtypes = [ctypes.POINTER(ctypes.c_uint),
                                              ctypes.POINTER(ctypes.c_uint)]
    gdip.GdipGetImageEncodersSize.restype = ctypes.c_int
    gdip.GdipGetImageEncoders.argtypes = [ctypes.c_uint, ctypes.c_uint,
                                          ctypes.c_void_p]
    gdip.GdipGetImageEncoders.restype = ctypes.c_int

    inp = GdiplusStartupInput(1, None, False, False)
    if gdip.GdiplusStartup(ctypes.byref(_token), ctypes.byref(inp), None) != 0:
        return None
    _started = True
    _gdip = gdip
    return gdip


def _png_clsid():
    """PNG 编码器的 CLSID。

    用固定常量而不是去遍历 GdipGetImageEncoders：那条路的 ImageCodecInfo
    结构体在不同位数下布局不一致，稍有偏差就是进程级崩溃（实测踩过 segfault）。
    {557CF406-1A04-11D3-9A73-0000F81EF32E} 是 GDI+ 里 PNG 的官方 CLSID。
    """
    gdip = _lib()
    if gdip is None:
        return None, None
    g = GUID()
    g.Data1 = 0x557CF406
    g.Data2 = 0x1A04
    g.Data3 = 0x11D3
    g.Data4 = (ctypes.c_ubyte * 8)(0x9A, 0x73, 0x00, 0x00, 0xF8, 0x1E, 0xF3, 0x2E)
    return gdip, g


def to_png(src, dst):
    """src -> dst（PNG）。失败返回 False，不抛异常。"""
    if not os.path.isfile(src):
        return False
    try:
        gdip, clsid = _png_clsid()
        if gdip is None or clsid is None:
            return False

        bmp = ctypes.c_void_p()
        if gdip.GdipCreateBitmapFromFile(ctypes.c_wchar_p(os.path.abspath(src)),
                                         ctypes.byref(bmp)) != 0:
            return False
        try:
            tmp = dst + ".tmp"
            st = gdip.GdipSaveImageToFile(bmp, ctypes.c_wchar_p(os.path.abspath(tmp)),
                                          ctypes.byref(clsid), None)
            if st != 0 or not os.path.isfile(tmp):
                return False
            os.replace(tmp, dst)
            return True
        finally:
            gdip.GdipDisposeImage(bmp)
    except Exception:
        return False


def png_size(path):
    """读 PNG 头里的宽高，读不出来返回 (0, 0)。"""
    try:
        with open(path, "rb") as f:
            head = f.read(24)
        if len(head) < 24 or head[:8] != b"\x89PNG\r\n\x1a\n":
            return 0, 0
        w = int.from_bytes(head[16:20], "big")
        h = int.from_bytes(head[20:24], "big")
        return w, h
    except OSError:
        return 0, 0


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("用法： python user\\imgconv.py 输入图片 输出.png")
        raise SystemExit(2)
    ok = to_png(sys.argv[1], sys.argv[2])
    print("ok" if ok else "失败")
    if ok:
        print("尺寸:", png_size(sys.argv[2]))
    raise SystemExit(0 if ok else 1)
