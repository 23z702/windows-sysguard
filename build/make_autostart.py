"""make_autostart.py —— 把 sysguard 配成「开机自动加载并立即启用保护」。

    python build\\make_autostart.py            # 体检，只打印不动手
    python build\\make_autostart.py --apply    # 装成开机自启
    python build\\make_autostart.py --off      # 取消开机自启（回到手动 start）

三个关键决定：

1. 启动类型用 **auto(2)**，不用 boot(0)/system(1)。后两者在文件系统就绪之前
   就会加载，驱动放在普通卷上必然失败；auto 由 SCM 在登录前拉起，时机刚好。
2. 镜像搬到 %SystemRoot%\\System32\\drivers\\sysguard.sys。开机加载不能依赖
   桌面上的工程目录 —— 用户改个目录名、清个缓存，下次开机就静默失效了。
3. ErrorControl 保持 1(Normal)。设成 3(Critical) 意味着加载失败会让系统起不来，
   这种驱动永远不该用。

为什么必须先停驱动再改配置：驱动用 CmRegisterCallbackEx 守着 \\SERVICES\\<名字>，
运行期间改 Start / ImagePath 一律返回 err=5。
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "user"))

import guard_ctl      # noqa: E402
import service_ctl    # noqa: E402

TARGET_NAME = "sysguard.sys"
TARGET_PATH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                           "System32", "drivers", TARGET_NAME)
TARGET_IMAGE = r"\SystemRoot\System32\drivers\sysguard.sys"

SYSTEM_CODEINTEGRITY_INFORMATION = 103
CODEINTEGRITY_OPTION_TESTSIGN = 0x2


def testsigning_on():
    """用 SystemCodeIntegrityInformation 判断测试签名模式，不依赖 bcdedit。"""
    class CI(ctypes.Structure):
        _fields_ = [("Length", wt.ULONG), ("CodeIntegrityOptions", wt.ULONG)]

    ci = CI()
    ci.Length = ctypes.sizeof(ci)
    nt = ctypes.WinDLL("ntdll")
    st = nt.NtQuerySystemInformation(SYSTEM_CODEINTEGRITY_INFORMATION,
                                     ctypes.byref(ci), ci.Length, None)
    if st != 0:
        return None
    return bool(ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN)


def current():
    name = guard_ctl.detect_service_name()
    if not name:
        return None
    ks = service_ctl.key_state(name) or {}
    return {
        "service": name,
        "image": ks.get("ImagePath"),
        "start": ks.get("Start"),
        "start_name": service_ctl.START_NAME.get(ks.get("Start"), "?"),
        "error_control": ks.get("ErrorControl"),
        "state": service_ctl.STATE_NAME.get(service_ctl.service_state(name), "?"),
    }


def describe():
    info = current()
    ts = testsigning_on()
    print("==== 现状 ====")
    if not info:
        print("  没找到 sysguard 服务（先 install.ps1 / service_ctl create）")
        return None
    print(f"  服务名      : {info['service']}")
    print(f"  状态        : {info['state']}")
    print(f"  启动类型    : {info['start']}（{info['start_name']}）")
    print(f"  镜像        : {info['image']}")
    print(f"  ErrorControl: {info['error_control']}（1=失败只记日志，不拦启动）")
    print(f"  测试签名    : {'已开启' if ts else '未开启' if ts is not None else '读取失败'}")
    print()
    print("==== 判定 ====")
    img_low = (info["image"] or "").replace("/", "\\").lower()
    if img_low.endswith("drivers\\" + TARGET_NAME):
        print(f"  镜像已在 drivers 目录：{info['image']}")
    else:
        print(f"  镜像还在工程目录，开机加载不可靠（建议搬到 {TARGET_PATH}）")
    if info["start"] == service_ctl.SERVICE_AUTO_START:
        print("  已是开机自启（auto），重启后会自动加载并全开保护")
    else:
        print(f"  当前是 {info['start_name']}，重启后不会自动加载")
    if info["start"] in (service_ctl.SERVICE_BOOT_START,
                         service_ctl.SERVICE_SYSTEM_START):
        print("  [!] boot/system 启动：早期加载，文件系统可能还没就绪，风险高")
    if info["error_control"] == 3:
        print("  [!] ErrorControl=3(Critical)：加载失败会导致系统无法启动")
    if ts is False:
        print("  [!] 测试签名已关闭，自签驱动 auto 启动会被拒（错误 577）")
    return info


def driver_loaded():
    """内核里当前加载的 sysguard 镜像名列表。

    判驱动「停没停」不能看服务状态：这台机器上 stop 之后服务键会被立刻清掉，
    service_state() 返回 None，看起来像失败。模块表才是事实。
    """
    return sorted(n for n in guard_ctl.loaded_driver_names() if "sysguard" in n)


def stop_driver(name):
    """撤销自锁 + 下发令牌后停服务。返回是否已经停干净。"""
    if not driver_loaded():
        print("  驱动本来就没在跑")
        return True
    print("  先撤销自锁并授权卸载（否则 STOP 会被拒 1052）")
    try:
        g = guard_ctl.Guard()
    except OSError as e:
        print(f"  设备打不开：{e}")
        g = None
    if g is not None:
        try:
            if g.query()["config"]["unload_lock"]:
                g.set_config(unload_lock=False)
                print("    自锁已关")
        except OSError as e:
            print("    关自锁失败：", e)
        try:
            g.unload_token()
            print("    卸载令牌已下发")
        except OSError as e:
            print("    令牌失败：", e)
        g.close()

    for i in range(3):
        if service_ctl.do_stop(name):
            break
        print(f"    第 {i + 1} 次 stop 未成功，重试")

    left = driver_loaded()
    if left:
        print(f"  [!] 内核里仍有：{', '.join(left)}")
        return False
    print("  已确认卸载（内核模块表里没有 sysguard）")
    return True


def pick_source(explicit=None):
    """挑要装进 drivers 的源镜像。

    优先用命令行给的；否则用当前服务指向的（如果它不在 drivers 目录里）；
    再否则取 build 下最新的 sysguard_v*.sys。
    """
    if explicit:
        p = os.path.abspath(explicit)
        return p if os.path.isfile(p) else None
    info = current() or {}
    img = (info.get("image") or "").replace("\\??\\", "").replace("\\\\?\\", "")
    if img and os.path.isfile(img) and \
            os.path.abspath(img).lower() != os.path.abspath(TARGET_PATH).lower():
        return img
    import glob
    cands = sorted(glob.glob(os.path.join(HERE, "sysguard_v*.sys")),
                   key=os.path.getmtime, reverse=True)
    return cands[0] if cands else None


def _sha(path):
    import hashlib
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def pick_name(base="sysguard"):
    """挑一个没被占用的服务名。"""
    if service_ctl.key_state(base) is None:
        return base
    for i in range(1, 20):
        cand = f"{base}{i}"
        if service_ctl.key_state(cand) is None:
            return cand
    return f"{base}20"


def install_word():
    print("  已就绪：drivers 目录 + Start=auto + 运行中")


def apply_autostart():
    ts = testsigning_on()
    info = current()

    print("==== 现状 ====")
    if info:
        print(f"  服务名      : {info['service']}")
        print(f"  状态        : {info['state']}")
        print(f"  启动类型    : {info['start']}（{info['start_name']}）")
        print(f"  镜像        : {info['image']}")
        print(f"  ErrorControl: {info['error_control']}")
    else:
        print("  服务键      : 不存在（stop 之后会被外部清掉，下面直接重建）")
    print(f"  测试签名    : {'已开启' if ts else '未开启' if ts is not None else '读取失败'}")
    print(f"  内核里的实例: {driver_loaded() or '无'}")

    if ts is False:
        print("\n[中止] 测试签名未开启，auto 启动会因签名被拒。"
              "先执行：bcdedit /set testsigning on 并重启")
        return 1
    if info and info["error_control"] == 3:
        print("\n[中止] ErrorControl=3(Critical)，加载失败会让系统起不来，先改成 1")
        return 1

    src = pick_source(sys.argv[sys.argv.index("--from") + 1]
                      if "--from" in sys.argv else None)
    if not src:
        print("\n[中止] 找不到可用的源镜像（用 --from 指定 .sys）")
        return 1

    # 已经就位且内容一致 —— 不停机就不会有「服务键被清掉」的窗口
    if info:
        img_low = (info["image"] or "").replace("/", "\\").lower()
        in_drivers = img_low.endswith("drivers\\" + TARGET_NAME)
        same = os.path.abspath(src).lower() == os.path.abspath(TARGET_PATH).lower() \
            or _sha(src) == _sha(TARGET_PATH)
        if (info["start"] == service_ctl.SERVICE_AUTO_START and in_drivers
                and info["state"] == "RUNNING" and same and driver_loaded()):
            print("\n已就位且内容一致，不需要动它。")
            install_word()
            print("重启后会自动加载并全开保护。")
            return 0

    os.makedirs(os.path.join(HERE, "old"), exist_ok=True)
    snap = os.path.join(HERE, "old", "autostart_backup.json")
    with open(snap, "w", encoding="utf-8") as f:
        json.dump(info or {"service": None}, f, ensure_ascii=False, indent=2)
    print(f"\n配置快照已存：{snap}")

    name = info["service"] if info else None

    print("\n==== 1) 停驱动（改服务键的前提） ====")
    if driver_loaded():
        if not stop_driver(name or "sysguard"):
            print("[中止] 停不下来，不能改配置。检查是否有界面占着设备句柄。")
            return 1
    else:
        print("  驱动当前没在跑，跳过")

    print("\n==== 2) 复制镜像到 drivers 目录 ====")
    print(f"  {src}")
    print(f"  -> {TARGET_PATH}")
    if _sha(src) != _sha(TARGET_PATH):
        try:
            shutil.copy2(src, TARGET_PATH)
            print(f"  已复制，{os.path.getsize(TARGET_PATH)} 字节")
        except OSError as e:
            print(f"[中止] 复制失败：{e}")
            return 1
    else:
        print("  内容一致，跳过复制")

    print("\n==== 3) 配置服务：auto + 固定镜像路径 ====")
    if name is None or service_ctl.key_state(name) is None:
        # 停止过程中被外部清掉了（本机稳定复现）。键都没了，直接重建更快。
        if name:
            print(f"  服务键 {name} 在停止后消失，重建")
        name = pick_name()
        if not service_ctl.do_create(name, TARGET_PATH,
                                     service_ctl.SERVICE_AUTO_START):
            print("[中止] 重建服务失败")
            return 1
    if not service_ctl.do_set_start(name, service_ctl.SERVICE_AUTO_START,
                                    TARGET_IMAGE):
        print("[中止] 改配置失败")
        return 1

    print("\n==== 4) 立刻加载一次验证 ====")
    if not service_ctl.do_start(name):
        print("[!] 启动失败 —— 配置已写入，但这次没起来。看上面错误码。")
        return 1

    print("\n==== 5) 确认保护真的全开 ====")
    try:
        g = guard_ctl.Guard()
        st = g.query()
        cfg = st["config"]
        print(f"  版本 {st['version']}  设备 {g.path}")
        for k, v in cfg.items():
            print(f"    {k:<12} {'开' if v else '关'}")
        allon = all(cfg.values())
        g.close()
    except OSError as e:
        print(f"  [!] 连不上驱动：{e}")
        return 1

    print()
    if allon:
        print(f"已配置完成（服务 {name}）：下次开机自动加载并全开保护，不需要开界面。")
    else:
        print("[!] 有开关是关的 —— 默认值本应全开，检查驱动默认配置")
    print("验证方式：重启后直接跑  python build\\diag\\svc_probe.py")
    print("          Start 应为 2、状态 RUNNING、只有 1 个实例")
    print("要取消：  python build\\make_autostart.py --off")
    return 0


def disable_autostart():
    print("==== 取消开机自启 ====")
    info = current()
    name = info["service"] if info else None
    if info:
        print(f"  当前服务：{name}（{info['start_name']}）")
        print(f"  镜像    ：{info['image']}")
    else:
        print("  服务键不存在 —— 本来就没有自启配置")

    if driver_loaded():
        if not stop_driver(name or "sysguard"):
            print("[中止] 停不下来")
            return 1
    else:
        print("  驱动当前没在跑")

    # 停完之后键可能被外部清掉，那就没什么可改的了
    if name and service_ctl.key_state(name) is not None:
        if not service_ctl.do_set_start(name, service_ctl.SERVICE_DEMAND_START):
            return 1
        print("\n已改回 demand：重启不会自动加载。需要时手动")
        print(f"  python user\\service_ctl.py start --service {name}")
    else:
        print("\n服务键已不存在（停止后被清理），重启自然不会加载。")
        print("需要重新启用：python build\\make_autostart.py --apply")
    return 0


def main():
    if "--apply" in sys.argv:
        return apply_autostart()
    if "--off" in sys.argv:
        return disable_autostart()
    print("[体检模式] 加 --apply 才动手，--off 取消自启\n")
    describe()
    return 0


if __name__ == "__main__":
    sys.exit(main())
