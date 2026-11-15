"""huorong_gui.py —— 仿火绒安全界面（sysguard 自保护演示前端）

功能：
    · 首页     驱动状态总览 / 保护本程序 / 一键自检
    · 防护中心 进程保护、线程保护、注册表锁、驱动自锁 四个开关（直通内核）
    · 进程保护 枚举系统进程，勾选加入/移出保护名单
    · 拦截日志 内核环形缓冲区里的每一次拦截记录
    · 关于     使用说明与强杀测试入口

运行： python user/huorong_gui.py     （需管理员 + 驱动已加载）
"""

import ctypes
import ctypes.wintypes as wt
import datetime
import os
import subprocess
import sys

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
except ImportError:
    print("[!] 当前 Python 解释器没有 tkinter（常见于绿色版/精简版 Python）。")
    print("    请改用官方安装版 Python 运行：")
    print(r"    C:\Python315\python.exe user\huorong_gui.py   （换成官方安装版的路径）")
    raise SystemExit(1)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    import guard_ctl
except ImportError:
    guard_ctl = None
try:
    import elevate
except ImportError:
    elevate = None

# ---------------- 配色（火绒风格：白底 + 品牌绿） ----------------
C = {
    "bg": "#F2F5FA",
    "card": "#FFFFFF",
    "green": "#22B14C",
    "green_dark": "#158A3A",
    "green_soft": "#E8F8ED",
    "text": "#1D2530",
    "sub": "#7B8696",
    "line": "#E7ECF3",
    "red": "#E5484D",
    "amber": "#F5A524",
    "nav": "#FFFFFF",
}

FONT = "Microsoft YaHei UI"
F_TITLE = (FONT, 17, "bold")
F_H1 = (FONT, 22, "bold")
F_BODY = (FONT, 10)
F_SMALL = (FONT, 9)
F_NUM = ("Segoe UI", 26, "bold")

k32 = ctypes.WinDLL("kernel32", use_last_error=True)


# ---------------- 进程枚举 ----------------
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


def enum_processes():
    """返回 [(pid, 进程名, 路径)]，按 PID 升序"""
    TH32CS_SNAPPROCESS = 0x00000002
    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k32.QueryFullProcessImageNameW.restype = wt.BOOL
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == wt.HANDLE(-1).value:
        return []

    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    out = []
    ok = k32.Process32FirstW(snap, ctypes.byref(pe))
    while ok:
        pid = pe.th32ProcessID
        if pid:
            path = ""
            h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if h:
                buf = ctypes.create_unicode_buffer(520)
                size = wt.DWORD(520)
                if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                    path = buf.value
                k32.CloseHandle(h)
            out.append((pid, pe.szExeFile, path))
        ok = k32.Process32NextW(snap, ctypes.byref(pe))
    k32.CloseHandle(snap)
    out.sort(key=lambda x: x[0])
    return out


# 结束这些进程会让系统立刻失去响应或直接蓝屏。批量强杀（尤其按名）时
# 很容易连坐命中，界面上单独拦一道，不在“普通确认框”里一笔带过。
CRITICAL_PROCS = {
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe",
    "registry", "memcompression", "system",
}


# ---------------- 小控件 ----------------
def round_rect(cv, x1, y1, x2, y2, r, **kw):
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
           x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
           x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return cv.create_polygon(pts, smooth=True, **kw)


class Card(tk.Frame):
    """白底圆角卡片

    fill=False：高度跟随内容自动撑开（用于信息卡）
    fill=True ：高度跟随父容器（用于表格类卡片）
    """

    def __init__(self, master, padding=18, fill=False, **kw):
        super().__init__(master, bg=C["bg"], **kw)
        self._fill = fill
        self._pad = padding
        self.canvas = tk.Canvas(self, bg=C["bg"], highlightthickness=0, height=80)
        self.canvas.pack(fill="both", expand=True)
        self.body = tk.Frame(self.canvas, bg=C["card"])
        self._win = self.canvas.create_window(padding, padding, window=self.body, anchor="nw")
        self.canvas.bind("<Configure>", self._redraw)
        self.body.bind("<Configure>", self._fit)
        self.after(0, self._fit)

    def _fit(self, _evt=None):
        if self._fill:
            return
        want = self.body.winfo_reqheight() + self._pad * 2
        if want > 40 and self.canvas.cget("height") != str(want):
            self.canvas.configure(height=want)

    def _redraw(self, _evt=None):
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        self.canvas.delete("bgshape")
        round_rect(self.canvas, 1, 1, max(w - 2, 3), max(h - 2, 3), 12,
                   fill=C["card"], outline=C["line"], tags="bgshape")
        self.canvas.tag_lower("bgshape")
        if self._fill:
            self.canvas.itemconfig(self._win, width=w - self._pad * 2,
                                   height=max(h - self._pad * 2, 10))
        else:
            self.canvas.itemconfig(self._win, width=w - self._pad * 2)


class Switch(tk.Canvas):
    """开关控件"""

    def __init__(self, master, value=True, command=None, bg=C["card"]):
        super().__init__(master, width=48, height=26, highlightthickness=0, bg=bg)
        self._on = bool(value)
        self.command = command
        self.bind("<Button-1>", self._click)
        self.bind("<Enter>", lambda e: self.config(cursor="hand2"))
        self._draw()

    def _draw(self):
        self.delete("all")
        track = C["green"] if self._on else "#CFD6E0"
        round_rect(self, 2, 3, 46, 23, 11, fill=track, outline="")
        cx = 35 if self._on else 13
        self.create_oval(cx - 8, 5, cx + 8, 21, fill="white", outline="")

    def _click(self, _e):
        self._on = not self._on
        self._draw()
        if self.command:
            self.command(self._on)

    def set(self, value):
        self._on = bool(value)
        self._draw()

    def get(self):
        return self._on


# ---------------- 主窗口 ----------------
class App(tk.Tk):
    NAV = [
        ("home", "首页"),
        ("guard", "防护中心"),
        ("proc", "进程保护"),
        ("log", "拦截日志"),
        ("about", "关于"),
    ]

    def __init__(self):
        super().__init__()
        self.title("火绒安全 · 仿制版  |  sysguard 自保护驱动演示")
        self.geometry("1060x690")
        self.minsize(980, 640)
        self.configure(bg=C["bg"])

        self.guard = None
        self.driver_ok = False
        self.driver_build = ""
        self._tried_autostart = False
        self.pages = {}
        self.active = None
        self.nav_widgets = {}
        self._cached_pids = set()

        self._build_style()
        self._build_layout()
        self._connect_driver()
        self.show("home")
        self.after(300, self._tick)

    # ---- 样式 ----
    def _build_style(self):
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure("Treeview",
                     background=C["card"], fieldbackground=C["card"],
                     foreground=C["text"], rowheight=30, borderwidth=0,
                     font=(FONT, 9))
        st.configure("Treeview.Heading",
                     background="#F7F9FC", foreground=C["sub"],
                     relief="flat", font=(FONT, 9, "bold"))
        st.map("Treeview", background=[("selected", C["green_soft"])],
               foreground=[("selected", C["green_dark"])])
        st.map("Treeview.Heading", background=[("active", "#EDF2F9")])
        st.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    # ---- 布局 ----
    def _build_layout(self):
        header = tk.Frame(self, bg=C["card"], height=68)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        logo = tk.Canvas(header, width=40, height=40, bg=C["card"], highlightthickness=0)
        logo.pack(side="left", padx=(22, 10))
        logo.create_oval(3, 3, 37, 37, fill=C["green"], outline="")
        logo.create_polygon(20, 10, 30, 15, 30, 22, 20, 31, 10, 22, 10, 15,
                            fill="white", outline="")
        logo.create_line(15, 20, 19, 24, 26, 16, fill=C["green"], width=2)

        tk.Label(header, text="火绒安全", font=(FONT, 15, "bold"),
                 bg=C["card"], fg=C["text"]).pack(side="left", pady=(0, 0))
        tk.Label(header, text="仿制版 · sysguard", font=F_SMALL,
                 bg=C["card"], fg=C["sub"]).pack(side="left", padx=(8, 0), pady=(6, 0))

        self.pill = tk.Label(header, text="  检测中…  ", font=F_SMALL,
                             bg="#EEF1F6", fg=C["sub"], padx=8, pady=4)
        self.pill.pack(side="right", padx=22)

        tk.Frame(self, bg=C["line"], height=1).pack(fill="x")

        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True)

        nav = tk.Frame(body, bg=C["nav"], width=176)
        nav.pack(side="left", fill="y")
        nav.pack_propagate(False)
        tk.Frame(body, bg=C["line"], width=1).pack(side="left", fill="y")

        for key, text in self.NAV:
            self._nav_item(nav, key, text)

        self.content = tk.Frame(body, bg=C["bg"])
        self.content.pack(side="left", fill="both", expand=True)

        self.pages["home"] = self._page_home()
        self.pages["guard"] = self._page_guard()
        self.pages["proc"] = self._page_proc()
        self.pages["log"] = self._page_log()
        self.pages["about"] = self._page_about()

    def _nav_item(self, parent, key, text):
        row = tk.Frame(parent, bg=C["nav"], height=46)
        row.pack(fill="x")
        row.pack_propagate(False)

        bar = tk.Frame(row, bg=C["nav"], width=3)
        bar.pack(side="left", fill="y")

        lbl = tk.Label(row, text=f"     {text}", font=(FONT, 10),
                       bg=C["nav"], fg=C["sub"], anchor="w")
        lbl.pack(side="left", fill="both", expand=True)

        for w in (row, lbl):
            w.bind("<Button-1>", lambda e, k=key: self.show(k))
            w.bind("<Enter>", lambda e, r=row, l=lbl: self._nav_hover(r, l, True))
            w.bind("<Leave>", lambda e, r=row, l=lbl: self._nav_hover(r, l, False))

        self.nav_widgets[key] = (row, lbl, bar)

    def _nav_hover(self, row, lbl, on):
        if self.active and self.nav_widgets.get(self.active, (None,))[0] is row:
            return
        bg = "#F5F7FB" if on else C["nav"]
        row.config(bg=bg)
        lbl.config(bg=bg)

    def show(self, key):
        if self.active == key:
            return
        for k, (row, lbl, bar) in self.nav_widgets.items():
            if k == key:
                row.config(bg=C["green_soft"])
                lbl.config(bg=C["green_soft"], fg=C["green_dark"], font=(FONT, 10, "bold"))
                bar.config(bg=C["green"])
            else:
                row.config(bg=C["nav"])
                lbl.config(bg=C["nav"], fg=C["sub"], font=(FONT, 10))
                bar.config(bg=C["nav"])

        if self.active:
            self.pages[self.active].pack_forget()
        self.active = key
        self.pages[key].pack(fill="both", expand=True)
        if key == "proc":
            self.refresh_procs()
        elif key == "about":
            self._refresh_about()
        elif key == "log":
            self.refresh_log()

    # ---------------- 首页 ----------------
    def _page_home(self):
        f = tk.Frame(self.content, bg=C["bg"])

        # --- 主卡片 ---
        hero = Card(f, padding=22)
        hero.pack(fill="x", padx=24, pady=(24, 12))
        hero.configure(height=248)
        hero.pack_propagate(False)

        # 右侧统计先 pack，保证其自然宽度不被左侧 expand 抢占
        right = tk.Frame(hero.body, bg=C["card"])
        right.pack(side="right", fill="y", padx=(10, 6), pady=14)

        self.stat_labels = {}
        for key, title in [("protected", "受保护进程"),
                           ("blocked", "累计拦截"),
                           ("version", "驱动版本")]:
            row = tk.Frame(right, bg=C["card"])
            row.pack(fill="x", pady=6)
            val = tk.Label(row, text="--", font=(FONT, 16, "bold"),
                           bg=C["card"], fg=C["green_dark"], anchor="e", width=8)
            val.pack(side="right")
            tk.Label(row, text=title, font=F_SMALL, bg=C["card"],
                     fg=C["sub"]).pack(side="right", padx=(0, 14))
            self.stat_labels[key] = val

        left = tk.Frame(hero.body, bg=C["card"])
        left.pack(side="left", fill="both", expand=True)
        self.hero_canvas = tk.Canvas(left, width=112, height=112, bg=C["card"],
                                     highlightthickness=0)
        self.hero_canvas.pack(side="left", padx=(6, 24), pady=8)
        self._draw_shield(self.hero_canvas, safe=True)

        txt = tk.Frame(left, bg=C["card"])
        txt.pack(side="left", fill="y", pady=16)
        self.hero_title = tk.Label(txt, text="正在检测…", font=F_H1,
                                   bg=C["card"], fg=C["text"])
        self.hero_title.pack(anchor="w")
        self.hero_sub = tk.Label(txt, text="sysguard.sys 自保护驱动", font=F_BODY,
                                 bg=C["card"], fg=C["sub"], justify="left",
                                 anchor="w", wraplength=430)
        self.hero_sub.pack(anchor="w", pady=(8, 18))

        btns = tk.Frame(txt, bg=C["card"])
        btns.pack(anchor="w")
        self._btn(btns, "保护本程序", self.protect_self, primary=True).pack(side="left")
        self._btn(btns, "刷新状态", self.refresh_status).pack(side="left", padx=10)
        self._btn(btns, "强杀自检", self.run_killtest).pack(side="left")

        # --- 防护状态 ---
        strip = Card(f, padding=18)
        strip.pack(fill="x", padx=24, pady=(0, 12))

        head = tk.Frame(strip.body, bg=C["card"])
        head.pack(fill="x")
        tk.Label(head, text="防护状态", font=(FONT, 11, "bold"),
                 bg=C["card"], fg=C["text"]).pack(side="left")
        self.pid_hint = tk.Label(head, text="", font=F_SMALL, bg=C["card"], fg=C["sub"])
        self.pid_hint.pack(side="right")

        self.guard_lines = {}
        for key, text, desc in [
            ("process", "进程保护", "剥离 TERMINATE / VM_WRITE / CREATE_THREAD 等句柄权限"),
            ("thread", "线程保护", "拒绝 TerminateThread、挂起与上下文改写"),
            ("registry", "注册表锁", "锁死驱动服务键，sc delete 与改 ImagePath 全部失败"),
            ("unload_lock", "驱动自锁", "拒绝 unload，常驻内核"),
        ]:
            row = tk.Frame(strip.body, bg=C["card"])
            row.pack(fill="x", pady=5, padx=(2, 0))
            dot = tk.Canvas(row, width=10, height=10, bg=C["card"], highlightthickness=0)
            dot.pack(side="left", padx=(0, 10))
            dot.create_oval(1, 1, 9, 9, fill="#CFD6E0", outline="", tags="dot")
            tk.Label(row, text=text, font=F_BODY, bg=C["card"], fg=C["text"],
                     width=10, anchor="w").pack(side="left")
            tk.Label(row, text=desc, font=F_SMALL, bg=C["card"], fg=C["sub"],
                     anchor="w").pack(side="left")
            self.guard_lines[key] = dot

        # --- 最近拦截（吃掉剩余竖向空间） ---
        recent = Card(f, padding=18, fill=True)
        recent.pack(fill="both", expand=True, padx=24, pady=(0, 24))

        rhead = tk.Frame(recent.body, bg=C["card"])
        rhead.pack(fill="x")
        tk.Label(rhead, text="最近拦截", font=(FONT, 11, "bold"),
                 bg=C["card"], fg=C["text"]).pack(side="left")
        tk.Button(rhead, text="查看全部 ›", font=F_SMALL, bg=C["card"], fg=C["green_dark"],
                  relief="flat", bd=0, cursor="hand2", activebackground=C["card"],
                  command=lambda: self.show("log")).pack(side="right")

        self.recent_box = tk.Frame(recent.body, bg=C["card"])
        self.recent_box.pack(fill="both", expand=True, pady=(10, 0))
        self.recent_empty = tk.Label(self.recent_box,
                                     text="暂无拦截记录。点「保护本程序」后用任务管理器结束本进程试试。",
                                     font=F_SMALL, bg=C["card"], fg=C["sub"], anchor="w")
        self.recent_empty.pack(anchor="w")

        return f

    def _draw_shield(self, cv, safe=True, big=False):
        cv.delete("all")
        color = C["green"] if safe else C["red"]
        soft = C["green_soft"] if safe else "#FDECEE"
        cv.create_oval(4, 4, 106, 106, fill=soft, outline="")
        cv.create_oval(16, 16, 94, 94, fill=color, outline="")
        cv.create_polygon(55, 30, 78, 40, 78, 58, 55, 80, 32, 58, 32, 40,
                          fill="white", outline="")
        cv.create_line(44, 54, 52, 62, 67, 45, fill=color, width=4,
                       capstyle="round", joinstyle="round")

    def _btn(self, parent, text, cmd, primary=False, width=None):
        if primary:
            b = tk.Button(parent, text=text, command=cmd, font=F_BODY,
                          bg=C["green"], fg="white", activebackground=C["green_dark"],
                          activeforeground="white", relief="flat", bd=0,
                          cursor="hand2", padx=16, pady=7)
        else:
            b = tk.Button(parent, text=text, command=cmd, font=F_BODY,
                          bg="#F1F4F9", fg=C["text"], activebackground="#E5EAF2",
                          relief="flat", bd=0, cursor="hand2", padx=16, pady=7)
        if width:
            b.config(width=width)
        return b

    # ---------------- 防护中心 ----------------
    def _page_guard(self):
        f = tk.Frame(self.content, bg=C["bg"])
        card = Card(f, padding=22)
        card.pack(fill="x", padx=24, pady=(24, 14))

        tk.Label(card.body, text="防护中心", font=F_TITLE, bg=C["card"],
                 fg=C["text"]).pack(anchor="w")
        tk.Label(card.body, text="以下开关直接下发到内核驱动，即时生效。",
                 font=F_SMALL, bg=C["card"], fg=C["sub"]).pack(anchor="w", pady=(2, 16))

        self.switches = {}
        for key, title, desc in [
            ("process", "进程保护", "拦截对被保护进程的强杀、注入、内存写入"),
            ("thread", "线程保护", "拦截 TerminateThread、SuspendThread、SetThreadContext"),
            ("registry", "注册表保护", "禁止删除或改写 sysguard 服务键"),
            ("unload_lock", "驱动自锁", "拒绝卸载请求，驱动常驻"),
        ]:
            row = tk.Frame(card.body, bg=C["card"])
            row.pack(fill="x", pady=8)
            info = tk.Frame(row, bg=C["card"])
            info.pack(side="left", fill="x", expand=True)
            tk.Label(info, text=title, font=(FONT, 10, "bold"), bg=C["card"],
                     fg=C["text"]).pack(anchor="w")
            tk.Label(info, text=desc, font=F_SMALL, bg=C["card"],
                     fg=C["sub"]).pack(anchor="w")
            sw = Switch(row, value=True, command=lambda v, k=key: self.on_toggle(k, v))
            sw.pack(side="right")
            self.switches[key] = sw

        tip = Card(f, padding=18)
        tip.pack(fill="x", padx=24, pady=(0, 24))
        tk.Label(tip.body, text="⚠  内核层说明", font=(FONT, 10, "bold"),
                 bg=C["card"], fg=C["amber"]).pack(anchor="w")
        tk.Label(tip.body,
                 text=("· 进程/线程保护通过 ObRegisterCallbacks 在句柄创建阶段剥离权限，"
                       "任务管理器、taskkill、Process Explorer 全部失效。\n"
                       "· 注册表锁通过 CmRegisterCallbackEx 定点拦截服务键的删除与改写。\n"
                       "· 关闭「进程保护」后，已存在的句柄权限不会回收，需要重新打开句柄才会放行。"),
                 font=F_SMALL, bg=C["card"], fg=C["sub"], justify="left").pack(anchor="w", pady=(6, 0))
        return f

    def on_toggle(self, key, value):
        if not self.guard:
            return
        try:
            self.guard.set_config(**{key: value})
            self.refresh_status()
        except OSError as e:
            messagebox.showerror("下发失败", str(e))

    # ---------------- 进程保护 ----------------
    def _page_proc(self):
        f = tk.Frame(self.content, bg=C["bg"])
        card = Card(f, padding=18, fill=True)
        card.pack(fill="both", expand=True, padx=24, pady=(24, 24))

        head = tk.Frame(card.body, bg=C["card"])
        head.pack(fill="x")
        tk.Label(head, text="进程保护名单", font=F_TITLE, bg=C["card"],
                 fg=C["text"]).pack(side="left")
        self._btn(head, "刷新", self.refresh_procs).pack(side="right")
        self._btn(head, "移出保护", self.unprotect_selected).pack(side="right", padx=8)
        self._btn(head, "强制结束", self.kill_selected).pack(side="right")
        self._btn(head, "加入保护", self.protect_selected, primary=True).pack(side="right", padx=8)

        tk.Label(card.body, text="双击进程行可快速切换保护状态；绿色 ✔ 表示已受内核保护。",
                 font=F_SMALL, bg=C["card"], fg=C["sub"]).pack(anchor="w", pady=(4, 4))
        tk.Label(card.body, text="「强制结束」走内核句柄，目标的 DACL 拦不住它 —— "
                                "连「自己都进不去」的进程也能结束（PPL 除外）。",
                 font=F_SMALL, bg=C["card"], fg=C["sub"]).pack(anchor="w", pady=(0, 8))

        bar = tk.Frame(card.body, bg=C["card"])
        bar.pack(fill="x", pady=(0, 10))

        tk.Label(bar, text="筛选", font=F_SMALL, bg=C["card"],
                 fg=C["sub"]).pack(side="left")
        self.proc_filter = tk.StringVar()
        self.proc_filter.trace_add("write", lambda *_: self.refresh_procs())
        ent = tk.Entry(bar, textvariable=self.proc_filter, font=F_BODY, relief="solid",
                       bd=1, bg=C["bg"], fg=C["text"], insertbackground=C["text"])
        ent.pack(side="left", fill="x", expand=True, padx=(8, 10), ipady=4)
        ent.bind("<Return>", lambda _e: self.kill_by_name())

        self.proc_count = tk.Label(bar, text="", font=F_SMALL,
                                   bg=C["card"], fg=C["sub"])
        self.proc_count.pack(side="left", padx=(0, 10))

        self._btn(bar, "结束同名进程", self.kill_by_name).pack(side="right")
        self._btn(bar, "清空筛选", self._clear_filter).pack(side="right", padx=8)

        wrap = tk.Frame(card.body, bg=C["card"])
        wrap.pack(fill="both", expand=True)

        self.proc_tree = ttk.Treeview(wrap, columns=("pid", "name", "state", "path"),
                                      show="headings", selectmode="extended")
        for col, txt, w, anchor in [("pid", "PID", 80, "center"),
                                    ("name", "进程名", 200, "w"),
                                    ("state", "保护状态", 90, "center"),
                                    ("path", "路径", 420, "w")]:
            self.proc_tree.heading(col, text=txt)
            self.proc_tree.column(col, width=w, anchor=anchor, stretch=(col == "path"))
        self.proc_tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.proc_tree.yview)
        sb.pack(side="right", fill="y")
        self.proc_tree.configure(yscrollcommand=sb.set)
        self.proc_tree.tag_configure("on", foreground=C["green_dark"])
        self.proc_tree.bind("<Double-1>", self._toggle_row)
        return f

    def refresh_procs(self):
        if not hasattr(self, "proc_tree"):
            return
        protected = set()
        if self.guard:
            try:
                protected = set(self.guard.list_pids())
            except OSError:
                protected = set()
        self._cached_pids = protected

        flt = (self.proc_filter.get() if hasattr(self, "proc_filter") else "").strip().lower()
        rows = []
        total = 0
        for pid, name, path in enum_processes():
            total += 1
            if flt and flt not in name.lower() and flt not in path.lower() \
                    and flt not in str(pid):
                continue
            rows.append((pid, name, path))

        sel = set(self.proc_tree.selection())
        self.proc_tree.delete(*self.proc_tree.get_children())
        for pid, name, path in rows:
            on = pid in protected
            iid = str(pid)
            self.proc_tree.insert("", "end", iid=iid,
                                  values=(pid, name, "✔ 已保护" if on else "", path),
                                  tags=("on",) if on else ())
        for iid in sel:
            if self.proc_tree.exists(iid):
                self.proc_tree.selection_add(iid)

        if hasattr(self, "proc_count"):
            if rows and flt:
                hit = sum(1 for p, n, _ in rows if flt in n.lower())
                self.proc_count.config(text=f"筛选 {len(rows)}/{total} · 同名 {hit} 个")
            elif flt:
                self.proc_count.config(text=f"筛选 0/{total}")
            else:
                self.proc_count.config(text=f"共 {total} 个进程")

    def _clear_filter(self):
        if hasattr(self, "proc_filter"):
            self.proc_filter.set("")

    def _toggle_row(self, _e):
        for iid in self.proc_tree.selection():
            pid = int(iid)
            try:
                if pid in self._cached_pids:
                    self.guard.unprotect(pid)
                else:
                    self.guard.protect(pid)
            except OSError:
                pass
        self.refresh_procs()
        self.refresh_status()

    def protect_selected(self):
        if not self.guard:
            return
        n = 0
        for iid in self.proc_tree.selection():
            try:
                self.guard.protect(int(iid))
                n += 1
            except OSError:
                pass
        self.refresh_procs()
        self.refresh_status()
        if n:
            self._flash(f"已保护 {n} 个进程")

    def kill_selected(self):
        pids = [int(i) for i in self.proc_tree.selection()]
        if not pids:
            self._flash("先在列表里选中要结束的进程")
            return
        self._kill_pids(pids)

    def kill_by_name(self):
        """按进程名批量结束。名字取自筛选框，可省略 .exe、大小写无关。

        先按精确同名匹配（和命令行 `kill --name` 同源），没有命中再退回
        「名称包含」—— 因为筛选框里也可能填的是路径片段，比如 system32。
        两种规则都会在确认框里写明，避免用户以为只杀了一个。"""
        pat = (self.proc_filter.get() if hasattr(self, "proc_filter") else "").strip()
        if not pat:
            messagebox.showinfo(
                "按名结束进程",
                "请先在筛选框里输入进程名（可省略 .exe，例如 notepad），\n"
                "再点「结束同名进程」或直接回车。")
            return
        try:
            pids = guard_ctl.pids_by_name(pat) if guard_ctl else []
            how = "精确同名"
        except OSError as e:
            messagebox.showerror("查询失败", str(e))
            return
        if not pids:
            pids = [pid for pid, name, _ in enum_processes()
                    if pat.lower() in name.lower()]
            how = "名称包含"
        if not pids:
            messagebox.showinfo("没有命中",
                                f"当前没有进程名包含「{pat}」。\n"
                                "如果只想筛列表，可以不用点这个按钮。")
            return
        self._kill_pids(pids, note=f"{how}匹配「{pat}」")

    def _kill_pids(self, pids, note=""):
        """走驱动的内核句柄强制结束。普通 TerminateProcess 被目标 DACL 拦住时，
        这条路仍然可用（PPL 进程除外，驱动会回传 NTSTATUS）。"""
        pids = [int(p) for p in pids]
        if not pids:
            return
        if not self.guard:
            messagebox.showwarning("未连接", "驱动未加载，无法结束进程。")
            return

        if os.getpid() in pids:
            messagebox.showwarning("不能结束自己",
                                   "选中的是本程序自身。结束它会让这条请求无人收尾，已跳过。")
            pids = [p for p in pids if p != os.getpid()]
            if not pids:
                return

        protected = [p for p in pids if p in self._cached_pids]
        force = False
        if protected:
            if not messagebox.askyesno(
                    "目标受保护",
                    f"选中的 {len(protected)} 个进程在内核保护名单里：\n"
                    + "、".join(str(p) for p in protected[:8])
                    + "\n\n正常路径会被自我保护拒绝。是否先摘除保护再强制结束？"):
                return
            force = True

        # 系统关键进程单独拦一道：批量按名时最容易误伤
        names = {pid: name for pid, name, _ in enum_processes()}
        critical = [(p, names.get(p, "?")) for p in pids
                    if names.get(p, "").lower() in CRITICAL_PROCS]
        if critical:
            detail = "、".join(f"{n}({p})" for p, n in critical[:6])
            if len(critical) > 6:
                detail += f" 等 {len(critical)} 个"
            if not messagebox.askyesno(
                    "目标是系统关键进程",
                    f"这批目标里有系统关键进程：\n{detail}\n\n"
                    "结束它们会让系统立刻蓝屏或整机失去响应，"
                    "通常只能强制断电才能恢复。\n\n确定仍要继续？"):
                return

        if not messagebox.askyesno(
                "确认强制结束",
                f"将用驱动级强制结束 {len(pids)} 个进程"
                + (f"\n{note}" if note else "") + "：\n"
                + "、".join(str(p) for p in pids[:10])
                + ("\n…" if len(pids) > 10 else "")
                + "\n\n进程会被立即终止，未保存的数据会丢失。"):
            return

        done, failed, lines = 0, [], []
        for pid in pids:
            try:
                r = self.guard.kill(pid, force=force)
            except OSError as e:
                failed.append(f"{pid}  {e}")
                continue
            if r["ok"]:
                done += 1
                tail = "已确认退出" if r["waited"] else "已下发（未确认退出）"
                lines.append(f"✔ {pid}  {tail}")
            else:
                failed.append(f"{pid}  0x{r['status']:08X}  {r['text']}")

        self.refresh_procs()
        self.refresh_status()
        if failed:
            body = "\n".join(lines[-6:] + [f"✘ {x}" for x in failed[:8]])
            messagebox.showwarning(
                "部分进程未能结束",
                f"成功 {done} 个，失败 {len(failed)} 个：\n\n{body}")
        elif done:
            self._flash(f"已强制结束 {done} 个进程")

    def unprotect_selected(self):
        if not self.guard:
            return
        for iid in self.proc_tree.selection():
            try:
                self.guard.unprotect(int(iid))
            except OSError:
                pass
        self.refresh_procs()
        self.refresh_status()

    # ---------------- 拦截日志 ----------------
    def _page_log(self):
        f = tk.Frame(self.content, bg=C["bg"])
        card = Card(f, padding=18, fill=True)
        card.pack(fill="both", expand=True, padx=24, pady=(24, 24))

        head = tk.Frame(card.body, bg=C["card"])
        head.pack(fill="x")
        tk.Label(head, text="拦截日志", font=F_TITLE, bg=C["card"],
                 fg=C["text"]).pack(side="left")
        self._btn(head, "清空", self.clear_log).pack(side="right")
        self._btn(head, "刷新", self.refresh_log, primary=True).pack(side="right", padx=8)
        self.log_count = tk.Label(head, text="", font=F_SMALL, bg=C["card"], fg=C["sub"])
        self.log_count.pack(side="right", padx=14)

        wrap = tk.Frame(card.body, bg=C["card"])
        wrap.pack(fill="both", expand=True, pady=(12, 0))

        self.log_tree = ttk.Treeview(wrap, columns=("time", "type", "target", "caller", "acc"),
                                     show="headings")
        for col, txt, w, anchor in [("time", "时间", 132, "center"),
                                    ("type", "拦截类型", 94, "center"),
                                    ("target", "目标 PID", 84, "center"),
                                    ("caller", "发起 PID", 84, "center"),
                                    ("acc", "被剥离的权限", 400, "w")]:
            self.log_tree.heading(col, text=txt)
            self.log_tree.column(col, width=w, anchor=anchor, stretch=(col == "acc"))
        self.log_tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.log_tree.yview)
        sb.pack(side="right", fill="y")
        self.log_tree.configure(yscrollcommand=sb.set)
        return f

    def refresh_log(self):
        if not self.guard:
            return
        try:
            evs = self.guard.events()
            quiet = self.guard.query().get("quiet", 0)
        except OSError:
            return
        self.log_tree.delete(*self.log_tree.get_children())
        for ev in reversed(evs):
            ts = datetime.datetime.fromtimestamp(ev["time"] / 1e7 - 11644473600)
            self.log_tree.insert("", "end", values=(
                ts.strftime("%m-%d %H:%M:%S"),
                ev["type_name"],
                ev["target_pid"],
                ev["caller_pid"],
                self._access_text(ev["type"], ev["access"]),
            ))
        self.log_count.config(
            text=f"共 {len(evs)} 条 · 另有 {quiet} 次低风险权限裁剪（只计数，不记录）")

    @staticmethod
    def _access_text(etype, mask):
        if etype == 3:
            return "服务键删除/改写"
        if etype == 4:
            return "驱动卸载请求"
        if etype == 5:
            return "配置变更"
        if etype == 6:
            return "驱动级强制结束"
        # 只记录「核心」权限，位含义按对象类型区分
        if etype == 2:      # 线程句柄
            bits = [(0x0001, "THREAD_TERMINATE"), (0x0002, "SUSPEND"),
                    (0x0080, "SET_THREAD_TOKEN"), (0x0100, "IMPERSONATE"),
                    (0x0200, "DIRECT_IMPERSONATION")]
        else:               # 进程句柄
            bits = [(0x0001, "TERMINATE"), (0x0002, "CREATE_THREAD"),
                    (0x0008, "VM_OP"), (0x0020, "VM_WRITE"),
                    (0x0800, "SUSPEND")]
        names = [n for m, n in bits if mask & m]
        if not names:
            return f"0x{mask:08X}"
        return " | ".join(names)

    def clear_log(self):
        if self.guard:
            try:
                self.guard.clear_events()
            except OSError:
                pass
        self.refresh_log()

    # ---------------- 关于 ----------------
    def _live_driver_info(self):
        """实时取驱动信息，别在界面里写死——换版本/换服务名后写死的一定会过期。"""
        version, device, image = "未连接", "未连接", "未连接"
        full = None

        if self.guard:
            device = self.guard.path or "未连接"
            try:
                version = self.guard.query()["version"]
            except OSError:
                version = "读取失败"

        svc = guard_ctl.detect_service_name() if guard_ctl else None
        if svc:
            try:
                import winreg
                with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        "SYSTEM" + chr(92) + "CurrentControlSet" + chr(92) +
                        "Services" + chr(92) + svc) as k:
                    full = winreg.QueryValueEx(k, "ImagePath")[0]
                # \??\C:\...\build\xxx.sys -> build\xxx.sys
                if "build" + chr(92) in full.lower():
                    idx = full.lower().index("build" + chr(92))
                    image = full[idx:]
                else:
                    image = full
            except OSError:
                pass

        build = guard_ctl.build_tag(full) if (guard_ctl and svc) else ""
        label = (guard_ctl.version_label(version, build) if guard_ctl else version)

        return {"version": label, "device": device, "image": image,
                "service": svc or "未识别", "build": build}

    def _page_about(self):
        f = tk.Frame(self.content, bg=C["bg"])
        card = Card(f, padding=24)
        card.pack(fill="both", expand=True, padx=24, pady=(24, 24))

        tk.Label(card.body, text="sysguard 自保护驱动", font=F_TITLE,
                 bg=C["card"], fg=C["text"]).pack(anchor="w")
        tk.Label(card.body, text="仿火绒自保护的 Windows 内核驱动演示工程",
                 font=F_BODY, bg=C["card"], fg=C["sub"]).pack(anchor="w", pady=(2, 18))

        info = self._live_driver_info()
        rows = [
            ("驱动版本", info["version"]),
            ("驱动文件", info["image"]),
            ("设备名", info["device"]),
            ("服务名", info["service"]),
            ("技术点", "ObRegisterCallbacks / CmRegisterCallbackEx / DriverUnload 拦截"),
            ("强杀测试", "python user\\killtest.py --spawn"),
            ("授权卸载", "python user\\guard_ctl.py  +  build\\uninstall.ps1"),
        ]
        # 这一页是在连接驱动之前就建好的，所以这几行必须留引用，切页时再刷新
        self.about_vals = {}
        for k, v in rows:
            row = tk.Frame(card.body, bg=C["card"])
            row.pack(fill="x", pady=5)
            tk.Label(row, text=k, font=F_SMALL, bg=C["card"], fg=C["sub"],
                     width=10, anchor="w").pack(side="left")
            val = tk.Label(row, text=v, font=(FONT, 9), bg=C["card"],
                           fg=C["text"], anchor="w")
            val.pack(side="left")
            self.about_vals[k] = val

        self._refresh_about()

        tk.Label(card.body, text="测试流程", font=(FONT, 10, "bold"),
                 bg=C["card"], fg=C["text"]).pack(anchor="w", pady=(20, 6))
        tk.Label(card.body,
                 text=("1. 以管理员身份运行 build\\install.ps1 安装并加载驱动\n"
                       "2. python user\\huorong_gui.py 打开界面，点「保护本程序」\n"
                       "3. 打开任务管理器结束本程序 —— 会被内核拒绝\n"
                       "4. python user\\killtest.py --spawn 跑完整强杀测试套件\n"
                       "5. 卸载前先在「防护中心」关闭驱动自锁，再跑 uninstall.ps1"),
                 font=F_SMALL, bg=C["card"], fg=C["sub"], justify="left").pack(anchor="w")
        return f

    def _refresh_about(self):
        """把「关于」页的动态字段重刷一遍（页面比驱动连接先建，初值是"未连接"）。"""
        vals = getattr(self, "about_vals", None)
        if not vals:
            return
        info = self._live_driver_info()
        for k, v in (("驱动版本", info["version"]), ("驱动文件", info["image"]),
                     ("设备名", info["device"]), ("服务名", info["service"])):
            lbl = vals.get(k)
            if lbl is not None:
                lbl.config(text=v)

    # ---------------- 驱动交互 ----------------
    def _connect_driver(self):
        if guard_ctl is None:
            self.driver_ok = False
            self._set_offline("模块缺失")
            return
        try:
            self.guard = guard_ctl.Guard()
            self.driver_ok = True
            self.pill.config(text="  ● 驱动已连接  ", bg=C["green_soft"], fg=C["green_dark"])
            # 首页副标题也取实时值：写死文件名/版本号，换个版本就对不上了
            if "hero_sub" in self.__dict__:
                info = self._live_driver_info()
                self.driver_build = info["build"]
                text = f"{info['device']} · 驱动版本 {info['version']} · {info['image']}"
                shadow = getattr(self.guard, "shadowed", [])
                if shadow:
                    # 旧版本没卸干净时会各占一个设备名。已按版本连到最新的，
                    # 但必须让用户看见，否则会出现「界面显示已连接、新功能却不生效」
                    extra = "、".join(
                        f"{p}(v{v >> 16}.{v & 0xFFFF})" for p, v in shadow[:3])
                    text += f"\n⚠ 另有低版本实例在运行：{extra} —— 建议卸掉，否则可能被它截走请求"
                self.hero_sub.config(text=text)
        except OSError as e:
            code = getattr(e, "errno", None)
            # 设备打不开时先看「服务是不是没在跑」——驱动停掉后残留的设备符号
            # 链接会让 CreateFile 返回 5 而不是 2，光看错误码会误判成没提权。
            if not self._tried_autostart and self._driver_needs_start():
                self._tried_autostart = True
                if self._start_driver_once():
                    self._connect_driver()      # 重连一次，成功就不再递归
                    return
            self.driver_ok = False
            # 错误 5 不是"驱动没装"，而是"本进程没提权"。设备 DACL 只给
            # Administrators 全权，Everyone 连读都没有，所以这两种情况
            # 必须给不同的提示，否则用户会去反复重装驱动。
            self._set_offline(str(e), need_admin=(code == 5))

    def _driver_needs_start(self):
        """服务存在但没在跑 —— 这种情况值得尝试自动拉起。"""
        try:
            import service_ctl
        except ImportError:
            return False
        name = guard_ctl.detect_service_name() if guard_ctl else None
        if not name:
            return False
        try:
            st = service_ctl.service_state(name)
        except OSError:
            return False
        return st is not None and st != 4      # 4 = SERVICE_RUNNING

    def _start_driver_once(self):
        """设备不存在时把驱动服务拉起来（开机自启失效时的兜底）。"""
        try:
            import service_ctl
        except ImportError:
            return False
        name = guard_ctl.detect_service_name() if guard_ctl else None
        if not name:
            print("[autostart] 识别不到服务名，跳过自动启动")
            return False
        try:
            print(f"[autostart] 设备不存在，尝试启动服务 {name}")
            return bool(service_ctl.do_start(name))
        except Exception as e:              # noqa: BLE001 - 兜底路径不该再抛
            print("[autostart] 启动失败:", e)
            return False

    def _set_offline(self, msg, need_admin=False):
        self.pill.config(text="  ● 驱动未加载  ", bg="#FDECEE", fg=C["red"])
        try:
            print(f"[offline] {msg}")
        except Exception:
            pass
        if "hero_title" in self.__dict__:
            self.hero_title.config(text="防护未开启", fg=C["red"])
            if need_admin:
                self.hero_sub.config(
                    text="当前不是管理员权限（自动提权被取消或受限）。"
                         "关掉本窗口，右键「以管理员身份运行」即可。")
            else:
                self.hero_sub.config(
                    text="内核驱动未加载。请以管理员身份运行  build\\install.ps1  安装并启动。")
            self._draw_shield(self.hero_canvas, safe=False)

    def refresh_status(self):
        if not self.guard:
            self._connect_driver()
            if not self.guard:
                return
        try:
            st = self.guard.query()
        except OSError:
            self._set_offline("驱动句柄已失效")
            self.guard = None
            self.driver_ok = False
            return

        self.stat_labels["protected"].config(text=str(st["protected"]))
        self.stat_labels["blocked"].config(text=str(st["blocked"]))
        # 版本一行同时给行为版本和构建号：1.2（v4）
        build = self.driver_build
        self.stat_labels["version"].config(
            text=f"{st['version']}（{build}）" if build else st["version"])
        self.hero_title.config(text="您的电脑很安全" if self.driver_ok else "防护未开启",
                               fg=C["text"] if self.driver_ok else C["red"])

        for key, dot in self.guard_lines.items():
            on = st["config"].get(key, False)
            dot.itemconfig("dot", fill=C["green"] if on else "#CFD6E0")
            if key in self.switches:
                self.switches[key].set(on)

        try:
            pids = self.guard.list_pids()
        except OSError:
            pids = []
        self.pid_hint.config(
            text=("已保护 PID：" + "、".join(str(p) for p in pids[:8]) +
                  ("…" if len(pids) > 8 else "")) if pids else "保护名单为空")
        self._refresh_recent()

    def _refresh_recent(self):
        for w in self.recent_box.winfo_children():
            w.destroy()
        try:
            evs = self.guard.events() if self.guard else []
        except OSError:
            evs = []
        if not evs:
            tk.Label(self.recent_box,
                     text="暂无拦截记录。点「保护本程序」后用任务管理器结束本进程试试。",
                     font=F_SMALL, bg=C["card"], fg=C["sub"], anchor="w").pack(anchor="w")
            return
        for ev in list(reversed(evs))[:4]:
            ts = datetime.datetime.fromtimestamp(ev["time"] / 1e7 - 11644473600)
            row = tk.Frame(self.recent_box, bg=C["card"])
            row.pack(fill="x", pady=3)
            tk.Label(row, text=ts.strftime("%H:%M:%S"), font=F_SMALL, bg=C["card"],
                     fg=C["sub"], width=9, anchor="w").pack(side="left")
            tk.Label(row, text=" 已拦截 ", font=F_SMALL, bg=C["green_soft"],
                     fg=C["green_dark"]).pack(side="left", padx=(0, 10))
            tk.Label(row,
                     text=(f"{ev['type_name']}   目标 PID {ev['target_pid']}   "
                           f"发起 PID {ev['caller_pid']}   "
                           f"{self._access_text(ev['type'], ev['access'])}"),
                     font=F_SMALL, bg=C["card"], fg=C["text"], anchor="w").pack(side="left")

    def protect_self(self):
        if not self.guard:
            messagebox.showwarning("未连接", "驱动未加载，无法保护。")
            return
        pid = os.getpid()
        try:
            self.guard.protect(pid)
        except OSError as e:
            messagebox.showerror("失败", str(e))
            return
        self.refresh_status()
        self._flash(f"已保护本程序（PID {pid}），现在用任务管理器结束试试")

    def run_killtest(self):
        script = os.path.join(HERE, "killtest.py")
        try:
            subprocess.Popen(["cmd", "/c", "start", "", sys.executable, script, "--spawn"])
        except Exception as e:
            messagebox.showerror("启动失败", str(e))

    def _flash(self, msg):
        self.pill.config(text=f"  {msg}  ", bg=C["green_soft"], fg=C["green_dark"])

    def _tick(self):
        if self.active == "log":
            self.refresh_log()
        else:
            self.refresh_status()
        self.after(2000, self._tick)


def _auto_elevate():
    """非管理员时自动弹 UAC 重新拉起自己。返回 True 表示已交给新进程。"""
    if elevate is None:
        return False
    if elevate.is_admin():
        return False
    rc = elevate.ensure_admin(wait=False)
    if rc is None:
        print("[!] 自动提权未成功（UAC 被取消或受限），以当前权限继续，界面会显示「离线」。")
        return False
    return True


def main():
    if sys.platform != "win32":
        print("仅支持 Windows")
        return 1

    # 提权要在建窗口之前：非管理员下设备根本打不开，先起界面只会让人以为驱动坏了
    if _auto_elevate():
        return 0

    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
