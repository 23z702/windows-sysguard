# 盾守 SysGuard —— 自我保护驱动 + 强杀测试

一套自包含的 Windows 内核自保护演示工程：内核驱动在**句柄层**拦截对受保护进程的强杀/注入，
配套一个仿火绒界面和一个强杀测试套件，用 10 种真实攻击手法验证防护是否成立。

> 中文名「盾守」，英文 `SysGuard`，与驱动名、仓库名一致；界面上的名字集中在
> `user/huorong_gui.py` 顶部的 `APP_NAME / APP_AUTHOR / APP_REPO` 三个常量里，改一处全站生效。

```
sys/
├─ VERSION                 # 发布版本 1.5.3，与 GitHub tag v1.5.3 对齐（版本自检只比这个）
├─ driver/
│   └─ sysguard.c          # 内核驱动（WDM，约 1300 行）
├─ user/
│   ├─ huorong_gui.py      # 仿火绒界面（tkinter，零依赖）
│   ├─ guard_ctl.py        # IOCTL 封装（ctypes）
│   ├─ update_check.py     # 版本自检：单独连 GitHub 查新版（可脱离本项目单独运行）
│   ├─ auto_update.py      # 自动更新：下载 .sys → 停服务 → 换镜像 → 校验 → 失败回滚
│   ├─ imgconv.py          # JPEG→PNG（走 Windows GDI+，头像用，零第三方依赖）
│   ├─ sysguard.ico        # 应用图标（16/32/48/64/128/256 六种尺寸）
│   ├─ logo_96.png         # 关于页项目图标
│   ├─ logo_40.png         # 顶栏项目图标
│   ├─ elevate.py          # 自动提权（UAC，两条通道）
│   ├─ killtest.py         # 强杀测试套件（10 项）
│   ├─ forcekill_test.py   # 驱动级强制结束进程的验收（4 场景 7 项）
│   ├─ target_stub.py      # 测试靶子进程（--lock-dacl 可自锁 DACL）
│   ├─ service_ctl.py      # 服务管理（create/start/stop/delete/status，不依赖 sc.exe）
│   └─ unload_driver.py    # 下发卸载令牌
└─ build/
    ├─ build.sh            # 编译驱动（cl + link，不依赖 MSBuild）
    ├─ make_icon.py        # 生成应用图标（纯 Python 光栅化，不需要 Pillow）
    ├─ sign.ps1            # 自签证书 + 签名
    ├─ release.py          # 发版：体检 → 打 tag + push → 建 GitHub Release
    ├─ install.ps1         # 安装并加载服务（幂等；重名自动顺延）
    ├─ cleanup_old.py      # 清理遗留服务键与旧 .sys（默认只体检）
    ├─ make_autostart.py   # 配成开机自启：搬镜像 + Start=auto（幂等）
    ├─ uninstall.ps1       # 令牌 → 停止 → 删除
    └─ diag/
        ├─ dumpinfo.py     # 蓝屏转储速查（调 kd.exe，无需联网符号）
        ├─ svc_probe.py    # 查实例数/设备版本/Guard 会连哪个（多实例排查）
        ├─ retire_old.py   # 退役旧实例：清名单 → 关自锁 → 下发卸载令牌
        ├─ gui_shot.py     # 无交互截图，改完界面自查布局
        ├─ gui_killtest.py # 自动验收界面「结束同名进程」
        └─ gui_guardrail.py# 自动验收关键进程护栏
```

## 快速开始

```powershell
cd <项目根目录>
bash build/build.sh sysguard sysguard_v7          # 编译 -> build\sysguard_v7.sys
powershell -File build\sign.ps1 -Name sysguard_v7  # 测试签名（testsigning 已开启）
powershell -File build\install.ps1 -SysName sysguard_v7   # 安装 + 加载

python build\make_autostart.py --apply   # 装成开机自启（搬到 drivers + Start=auto）
python user\huorong_gui.py               # 打开界面，点「保护本程序」
python user\killtest.py --spawn          # 强杀测试（10 项，验证防护）
python user\forcekill_test.py            # 强制结束进程验收（4 场景 7 项）
```

不用先开「管理员 PowerShell」：每个入口都会自己弹 UAC 提权，见下一节。

> 界面需要带 tkinter 的 Python。若 `python` 指向的是精简版解释器（报 `No module named 'tkinter'`），
> 改用官方安装版：
> `C:\Python315\python.exe user\huorong_gui.py`（换成你本机官方安装版的路径）

卸载（自动识别当前活跃实例属于哪个服务）：

```powershell
powershell -File build\uninstall.ps1
```

也可以只用 Python，不碰 sc.exe：

```powershell
python user\service_ctl.py status                 # 服务名 / 状态 / 版本 / 两档计数
python user\service_ctl.py start                  # StartService（失败会打印 ERR=<码>）
python user\service_ctl.py uninstall              # 令牌 -> stop -> delete
python user\service_ctl.py create --service sysguard4 --image build\sysguard_v4.sys
```

创建/删除/启停全部走 advapi32，所以 `sc.exe` 被安全策略拦掉也不影响。

每换一版服务名就会多一个旧键，清理遗留项（默认只体检，不动手）：

```powershell
python build\cleanup_old.py                        # 列出候选，标出「保留(运行中)」与「遗留」
python build\cleanup_old.py --apply --purge-files  # 真删旧服务键，旧 .sys 移入 build\old\
```

判定规则是「状态 RUNNING 的保留，其余清理」，所以不会误删正在工作的实例。
处于 `STOP_PENDING` 的旧实例（镜像仍驻留内核）删不掉，键会进入删除队列；
SCM 一旦放手就会自己消失，不必等到重启。执行记录写在 `build\old\cleanup_history.log`，
删除前的服务快照在同目录的 `services_backup.json`。

（注意在项目根目录执行，别在 `build\` 里执行写成 `python build\cleanup_old.py`，会多拼一层路径。）

### 重复安装 / 换版本

`install.ps1` 是**幂等**的，随时可以重跑。已经装过同一份镜像时：

```
[1/5] sysguard3 is already running THIS image (sha256 matches) - nothing to do
```

- 判定依据：服务 RUNNING + `ImagePath` 与目标一致 + `HKLM\SOFTWARE\SysGuard\Installed\<服务名>`
  里记录的 SHA256 与当前文件一致。记录是**安装成功后**才写的，所以刚重新编译过要加 `-Force`。
- 驱动会保护自己的服务键（`\SERVICES\<名字>` 的删除/改写会被注册表回调拒绝），所以
  运行中的实例**删不掉**：`DeleteService` 只做标记，键进入删除队列，紧接着重建同名服务
  必然 `1072 (ERROR_SERVICE_MARKED_FOR_DELETE)`。旧版脚本「先删再建」，在已安装的机器上
  每次都会撞这个。
- 现在遇到占用/删除挂起的名字会自动往后退（`sysguard4`、`sysguard5`…），并在 `[2/5]`
  打印实际用的名字。要原地替换同一个名字，先正常卸载：

```powershell
python user\service_ctl.py uninstall --service sysguard3
powershell -File build\install.ps1
```

- **同一个 .sys 文件不能被加载两次**。文件已被某实例映射时，`StartService` 返回 `2`
  （找不到文件）——看着像路径写错，其实不是。`service_ctl.py start` 会把占用者查出来：

```
  StartService 失败 err=2（找不到镜像文件（路径写错，或用了正斜杠））
  提示：\??\...\build\sysguard_v4.sys 已被 sysguard3 加载。
        1) 复制成另一个文件名再装（内容相同也可以）
        2) 先卸掉旧实例：python user\service_ctl.py uninstall --service sysguard3
```

## 开机自动加载并启用保护

默认安装是 `Start=3`（demand），重启后驱动不会自己回来，保护是空的。要让「开机即生效」：

```powershell
python build\make_autostart.py            # 体检，只打印当前配置和风险
python build\make_autostart.py --apply    # 装成开机自启
python build\make_autostart.py --off      # 取消自启，回到手动 start
```

`--apply` 做三件事，顺序不能换：

1. **停驱动**。驱动用 `CmRegisterCallbackEx` 守着 `\SERVICES\<名字>`，运行期间改
   `Start` / `ImagePath` 一律 `err=5`。停之前先 `set_config(unload_lock=False)`
   + 卸载令牌，否则 STOP 被拒（1052）。
2. **复制镜像到 `%SystemRoot%\System32\drivers\sysguard.sys`**，`ImagePath` 写成
   `\SystemRoot\System32\drivers\sysguard.sys`。开机加载不能依赖桌面上的工程目录 ——
   改个目录名、清个缓存，下次开机就静默失效。
3. **`Start=2`（auto）**，然后立刻启动一次验证四个开关是否全开。

三个刻意选择的取值：

| 项 | 取值 | 为什么 |
|---|---|---|
| `Start` | `2` auto | `0` boot / `1` system 在文件系统就绪前就加载，镜像在普通卷上必然失败 |
| `ErrorControl` | `1` Normal | 设成 `3` Critical 意味着加载失败会让整机起不来，这类驱动永远不该用 |
| `ImagePath` | `\SystemRoot\...` | 盘符变化也能用；比写死 `C:\` 稳 |

驱动的配置**不持久化**：每次加载都回到默认全开（进程/线程/注册表/自锁四项）。
所以「自启」等于「开机就全开保护」，不需要打开界面。

更新驱动镜像时指定源文件，脚本会重走一遍上面三步：

```powershell
python build\make_autostart.py --apply --from build\sysguard_v8.sys
```

脚本是**幂等**的：已经在 drivers 目录 + auto + 运行中且内容一致时，它什么都不做 ——
不停机就不会有下文那个"服务键消失"的窗口。

### 为什么改完 `Start` 要重启才知道成不成

`--apply` 已经当场启动验证过一次（能起来 = 镜像路径和签名都没问题），
但「SCM 在开机时会不会自动拉它」只有真重启才验证得了。重启后跑：

```powershell
python build\diag\svc_probe.py
```

期望看到 `共 1 个实例`、设备版本 `1.5`、服务 `RUNNING`、`Start=2`。

## 自动提权

所有入口都会自己检查权限，不是管理员就弹 UAC 重新拉起自己，不需要手动「以管理员身份运行」。

```powershell
python user\huorong_gui.py        # 非管理员 -> 弹 UAC -> 新窗口里是提权后的界面
python user\killtest.py --spawn   # 参数原样带给提权后的进程
python build\cleanup_old.py       # 同上
build\install.bat                 # 双击即用，内部 fltmc 探测后自提权
```

| 入口 | 提权方式 |
|---|---|
| `user\*.py`（GUI / killtest / service_ctl / guard_ctl / unload_driver） | `elevate.ensure_admin()`，`import` 时就介入 |
| `build\cleanup_old.py` | 同上（自己把 `user\` 加进 `sys.path`） |
| `build\install.bat`、`loadtest.bat` | `fltmc` 探测（非管理员必失败）→ `Start-Process -Verb RunAs` |
| `build\install.ps1`、`loadtest.ps1`、`uninstall.ps1` | 脚本内自检，未提权时按 `$PSBoundParameters` 原样带参重启 |

实现要点（`user\elevate.py`）：

- **用 `ShellExecuteExW` 而不是 `ShellExecuteW`**：ExW 能拿到 `hProcess`，父进程
  `WaitForSingleObject` 等子进程结束，把真实退出码回传给调用方；`ShellExecuteW` 拿不到
  句柄，退出码只能丢。`killtest` 的「有突破则返回 1」因此仍然有效。
- **PowerShell 兜底**：部分环境（受限令牌、第三方安全软件挂钩、某些远程会话）会让
  shell32 的提权入口直接返回 `err=5`，此时自动改走
  `Start-Process -Verb RunAs -PassThru -Wait`。本机实测就是这种情况，两条通道都能用。
- **子进程自我识别**：提权重启时在脚本路径**之后**追加隐藏标记 `--sysguard-elevated`
  （放前面会被 python 当成自己的选项），模块 `import` 时就从 `sys.argv` 摘掉，argparse
  看不到它；子进程据此在结束时 `pause`，新窗口不会一闪而过。
- **绝不递归提权**：子进程若仍不是管理员（UAC 被组策略拦掉）直接继续运行。

两个开关：

```powershell
$env:SYSGUARD_NO_ELEVATE = "1"   # 关闭自动提权，用来复现「没权限」的报错路径
$env:SYSGUARD_NO_PAUSE   = "1"   # 提权子进程结束时不等回车（自动化/CI 用）
```

## 保护是怎么做的

| 机制 | 内核 API | 效果 |
|---|---|---|
| 进程句柄裁剪（核心） | `ObRegisterCallbacks(PsProcessType)` | `TERMINATE` / `CREATE_THREAD` / `VM_WRITE` / `VM_OPERATION` / `SUSPEND_RESUME` 就地剥掉，并写事件 |
| 进程句柄裁剪（静默） | 同上 | `VM_READ` / `SET_INFORMATION` / `SET_QUOTA` / `WRITE_DAC` / `WRITE_OWNER` 同样剥掉，但**只计数不记录** |
| 线程句柄裁剪（核心） | `ObRegisterCallbacks(PsThreadType)` | `THREAD_TERMINATE` / `SUSPEND_RESUME` / `SET_THREAD_TOKEN` / `IMPERSONATE` 剥掉并记录 |
| 线程句柄裁剪（静默） | 同上 | `SET_CONTEXT` / `SET_INFORMATION` / `SET_LIMITED_INFORMATION` 剥掉但不记录 |
| 服务键锁 | `CmRegisterCallbackEx` | 驱动服务键的删除、SetValue 一律 `STATUS_ACCESS_DENIED`，`sc delete` 失效 |
| 拒绝停止 | `DriverEntry` 不注册 `DriverUnload` | 内核直接拒绝卸载，`sc stop` 报 1052；只有令牌 IOCTL 到达后才把卸载例程装回去 |
| 拦截日志 | 环形缓冲 256 条 | 只记核心裁剪：类型、目标 PID、发起 PID、被剥离的权限位 |

**为什么分两档**：`VM_READ(0x10)` 和 `THREAD_SET_CONTEXT(0x10)` 会被任务管理器、
杀软扫描、调试器、UWP 宿主反复请求，一次扫描就能刷出几十条日志 —— 真正的攻击反而被
淹没，"累计拦截"也会虚高到没有参考价值（实测曾一路涨到 551）。现在这两类照样裁掉，
但不写事件、不进拦截计数，只在 `GUARD_STATE.QuietCount` 里累加，界面上显示成
"另有 N 次低风险权限裁剪（只计数，不记录）"。分档后同一套强杀测试的拦截计数是 **1~17**。

关键点在**层级**：`ObRegisterCallbacks` 在对象管理器里，比 SSDT、比 Win32 API、比
`NtOpenProcess` 都更底层。所以"绕过 API 直调内核"这条经典路子在这里是无效的 —— 权限在
句柄生成的那一刻就已经被削掉了，后面再怎么用这个句柄都使不上劲。

## 驱动级强制结束进程（1.3+）

自保护讲的是「别人杀不掉我」；这一节是反过来的能力：「**我怎么杀掉一个杀不掉的进程**」。

典型场景是目标把自己的安全描述符改成空 DACL —— 它自己都打不开自己，
管理员用任务管理器 `OpenProcess(PROCESS_TERMINATE)` 只会拿到 `err=5`，
于是变成一个"活着的钉子"。

驱动走的是另一条路：

```
ZwOpenProcess(PROCESS_TERMINATE|SYNCHRONIZE,
              OBJECT_ATTRIBUTES{ OBJ_KERNEL_HANDLE }, ...)
  → 发起者是内核态，对象管理器跳过整个访问检查，DACL 完全不参与判定
  → 句柄带 OBJ_KERNEL_HANDLE，不会进调用者的句柄表
ZwTerminateProcess(handle, STATUS_SUCCESS)
ObReferenceObjectByHandle(handle, SYNCHRONIZE, ...) → KeWaitForSingleObject
  → 最多等 5 秒确认真的退出；等不到只代表"没确认"，不改变已经下发的事实
```

### 三种用法

```powershell
# 1. 界面：进程页
#    · 选中行 → 「强制结束」
#    · 筛选框输入进程名（可省 .exe）→ 回车，或点「结束同名进程」一次结束全部同名
#    · 筛选框同时也过滤列表，可以按 PID / 路径片段找进程
python user\huorong_gui.py

# 2. 命令行：支持按 PID、按进程名、批量
python user\guard_ctl.py kill 1234
python user\guard_ctl.py kill --name notepad.exe
python user\guard_ctl.py kill --name notepad.exe --force --no-wait

# 3. Python API
python -c "import sys; sys.path.insert(0,'user'); import guard_ctl; \
g=guard_ctl.Guard(); print(g.kill(1234, force=True)); g.close()"
```

返回的结果结构（`guard_ctl.kill()`）：

| 字段 | 含义 |
|---|---|
| `ok` | 真的成功了（`status == 0`），不是"调用没报错" |
| `status` | 驱动回传的真实 NTSTATUS，如 `0xC0000022` 拒绝 / `0xC000010A` 正在退出 |
| `waited` | 1 = 内核确认进程已退出；0 = 已下发但没等到（或用了 `--no-wait`） |
| `method` | 位组合：1=用了内核句柄，2=先摘掉了保护名单条目 |

### 边界（有意为之，不是缺陷）

- **PPL 进程**（`csrss`、`MsMpEng` 等）：内核单独校验，会明确失败并回传 NTSTATUS，不做绕过尝试。
- **不能杀自己**：这条 IRP 会随进程一起消失，用户态永远等不到返回 —— 驱动直接拒绝（`0xC000000D`）。
- **PID 0 / 4**：直接拒绝。
- **目标在保护名单里**：默认拒绝（`0xC0000022`），必须显式 `--force`，驱动会先摘保护再杀，
  否则自己的句柄回调会把刚开出来的 TERMINATE 权限裁掉，变成自锁死循环。

### 界面上的两道护栏

按名批量结束很容易连坐，所以界面上比命令行多两道确认：

| 触发条件 | 行为 |
|---|---|
| 命中的进程在保护名单里 | 先问「是否先摘除保护再强制结束」，不点"是"就整批放弃 |
| 命中 `smss/csrss/wininit/winlogon/services/lsass/lsaiso/svchost` | 单独弹警告：结束它们会立刻蓝屏或整机失去响应 |

比如筛选 `svchost` 有几十个实例，误点「结束同名进程」代价是整个系统；
两道确认缺一不可。命令行 `kill --name` 保留脚本可用性，不做这层拦截。

### 验收

`python user\forcekill_test.py` —— 4 个场景共 7 项，每项都带用户态对照：

```
✔ 普通进程(用户态)      TerminateProcess -> True, err=0
✔ 普通进程(驱动)       status=0x00000000 已退出=True 内核确认=True
✔ DACL 自锁(用户态)   OpenProcess -> 失败 err=5
✔ DACL 自锁(驱动)    status=0x00000000 已结束 杀前存活=True 已退出=True
✔ 保护目标(默认)       status=0xC0000022 仍存活=True
✔ 保护目标(--force)  status=0x00000000 已退出=True 名单已清除=True
✔ 结束调用者自身        status=0xC000000D 参数无效
合计 7 项：通过 7 / 失败 0
```

「DACL 自锁」那两行是这个功能存在的全部理由：同样的目标，用户态 `err=5`，驱动 `status=0`。

## 强杀测试覆盖的攻击面

1. Win32 `TerminateProcess`（任务管理器同款）
2. 全权限 `OpenProcess(PROCESS_ALL_ACCESS)`
3. 原生 `NtOpenProcess` / `NtTerminateProcess`（绕过 Win32 层）
4. 线程级 `TerminateThread`
5. 挂起全部线程（假死式"结束"）
6. 远程线程注入 `ExitProcess`
7. 句柄复制通道 `PROCESS_DUP_HANDLE`
8. 停止驱动服务（`ControlService`）
9. 删除驱动服务（`DeleteService`）
10. 删除服务注册表键（绕过 SCM）

判定以**实际状态**为准，不看 API 返回值：

- 第 1–7 项看**目标进程是否还活着** —— 避免"调用返回成功但其实没杀掉"；
- 第 8 项看 `ControlService` 是否被拒 + 设备是否仍在线；
- 第 9 项看**服务注册表键的真实内容**（`DeleteFlag` / `Start`）—— `DeleteService`
  会先在 SCM 内存里把服务标记为删除并直接返回 TRUE，注册表写失败它也不改口，
  按返回值判定必然误报；
- 第 10 项看键是否还在，并用**驱动拦截计数的增量**区分"我们的回调拦的"和
  "键下有子键时系统本来就拒"（两者都返回 err=5）。

## 实测结果

`python user\killtest.py --spawn`（服务名自动识别，无需手动指定）：

```
目标 PID      : 1852
驱动版本      : 1.5（构建 v7）
被测服务      : sysguard7（自动识别）
服务镜像      : \??\...\build\sysguard_v7.sys

 1  Win32 TerminateProcess     拦截  err=5
 2  全权限句柄强杀                 拦截  拿到句柄但 TerminateProcess 失败，err=5
 3  原生 NtTerminateProcess     拦截  0xC0000022
 4  线程级 TerminateThread      拦截  4 个线程全部打开失败
 5  挂起全部线程                    拦截  4/4 失败（句柄可开但无权挂起）
 6  远程线程注入 ExitProcess       拦截  CreateRemoteThread 失败，err=5
 7  句柄复制通道                    拦截  只能复制目标已有句柄，拿不到带 TERMINATE 的
 8  停止驱动服务                    拦截  ControlService(STOP) 被拒，err=1052
 9  删除驱动服务                    拦截  DeleteService 报成功，但服务键完好
10  删除服务注册表键                  拦截  ImagePath 改写与删键均 err=5

合计 10 项：拦截 10 / 突破 0 / 跳过 0
```

配套 `python user\forcekill_test.py`（强制结束进程）**7 项全过**，见上文对应章节。

### 三套编号，别混着看

| 编号 | 出处 | 含义 |
|---|---|---|
| **1.5.0** | 仓库根 `VERSION` 文件 | **发布版本**，与 GitHub tag `v1.5.0` 对齐。版本自检只比这个 |
| **1.5** | 驱动内 `GUARD_VERSION`（`0x00010005`） | 行为/接口版本。改了拦截逻辑或接口才升，重新编译不变 |
| **v7** | 文件名 `sysguard_v7.sys` | 构建号。每编译一次加一，同一行为版本可以有很多构建 |
| **sysguard7** | 服务名 | 装第几次加一，换名是为了绕开"服务键被自己锁死" |

界面上统一显示成 `1.5（构建 v7）`，`python user\guard_ctl.py` 会同时打印版本、镜像路径和服务名。
构建号由 `guard_ctl.build_tag()` 从实际加载的镜像文件名解析，不写死——换版本不会对不上。


## 版本自检（更新检查）

`user\update_check.py` 是一个**能单独拿出来跑**的版本检查器：只依赖标准库，不 import 驱动控制层、
不需要管理员、不依赖 git 或任何连接器，纯 HTTPS 打 GitHub 公开 API。拷走这一个文件到别的机器也能用。

```powershell
python user\update_check.py            # 人读
python user\update_check.py --json     # 机读（GUI / 脚本用）
python user\update_check.py --force    # 忽略 6 小时缓存
python user\update_check.py --quiet    # 只在有新版本时输出
python user\update_check.py --local 1.4.0   # 单独拷走用：手动指定本机版本
```

输出长这样：

```
sysguard 版本自检
  仓库     : https://github.com/23z702/windows-sysguard
  本机版本 : 1.5.0
  最新版本 : v1.6.0  (release)
  发布时间 : 2026-11-20
  结论     : 有新版本 v1.6.0（当前 1.5.0）
  下载页   : https://github.com/23z702/windows-sysguard/releases/tag/v1.6.0
```

行为约定：

- **数据来源依次退化**：`releases/latest` → `releases?per_page=1` → `tags?per_page=1`。
  仓库一个 tag 都没有时报告「还没有任何 Release 或 Tag」，这是正常状态而不是报错。
- **比较的是发布版本**（根目录 `VERSION`，形如 `1.5.0`，与 tag `v1.5.0` 对齐），
  不是驱动行为版本 `1.5`，也不是构建号 `v7`。`VERSION` 缺失时才回退去解析 `GUARD_VERSION`。
- **6 小时磁盘缓存**（`%LOCALAPPDATA%\sysguard\update.json`）：GitHub 未认证 API 每小时只给 60 次，
  界面每次启动都裸查会被限流。`--force` 跳过缓存。
- 设 `GITHUB_TOKEN`（也认 `GH_TOKEN` / `SYGUARD_GITHUB_TOKEN`）可把限流提到 5000 次/小时。
- **任何失败都不抛给上层**：网络不通、限流、代理劫持都返回 `ok=False` + 中文原因，
  界面照常工作，驱动更不受影响（这个组件完全不碰驱动句柄）。
- 退出码：`0` 已是最新 / `10` 有新版本 / `2` 检查失败 —— 方便挂到 CI 或脚本里。
- **单独使用**：把 `update_check.py` 拷到任何目录都能跑（实测过：只拷这一个文件，
  没有 `VERSION`、没有驱动源码也能正常查到 `v1.5.0`）。此时「本机版本」取
  `--local` 或环境变量 `SYGUARD_LOCAL_VERSION`，都没有就按 `0.0.0` 算。
  换仓库只改文件顶部的 `REPO` 常量（或在 `check()` 里传）。

界面集成：「关于」页新增「版本自检」一行 + 「检查更新」按钮；启动 1.5 秒后还会**静默**查一次，
有新版时标题栏右侧浮出橙色角标 `↑ 新版 v1.6.0`，点一下就打开 Release 页。

### 关于页与图标

「关于」页是一张项目名片，所有内容都是运行时取的，没有一处写死在界面上：

| 元素 | 来源 |
|---|---|
| 项目图标 | `user/logo_96.png`，由 `build/make_icon.py` 生成 |
| 版本号 | 根目录 `VERSION` |
| 作者头像 | GitHub 头像，首次联网下载后缓存 7 天（`%LOCALAPPDATA%\sysguard\avatar_*.img`）|
| 最新版本 | `releases/latest`，和「检查更新」共用一份缓存 |
| ★ Star 数 | `GET /repos/...` 的 `stargazers_count`，缓存 6 小时 |

改名 / 换作者只动 `user/huorong_gui.py` 顶部这几个常量，窗口标题、顶栏、关于页一起变：

```python
APP_NAME = "盾守"          # 中文名
APP_NAME_EN = "SysGuard"
APP_AUTHOR = "bixie"
APP_HANDLE = "23z702"
APP_REPO = "23z702/windows-sysguard"
```

图标不用任何绘图软件、也不需要 Pillow：`build/make_icon.py` 用纯 Python 逐像素光栅化
（2 倍超采样后盒式降采样做抗锯齿），一次输出 `sysguard.ico`（16/32/48/64/128/256 六种尺寸）
和界面用的 `logo_96.png` / `logo_40.png`。改配色或形状后重跑一次即可：

```powershell
python build\make_icon.py --preview     # 同时导出 256px PNG 方便肉眼检查
```

头像这一路有三个坑，都踩过了：

1. **GitHub 的 `https://github.com/<user>.png` 返回的是 JPEG**（不管你传什么 `Accept`），
   而 tk 的 `PhotoImage` 只认 PNG/GIF。项目又不想为了转码引入 Pillow，
   所以 `user/imgconv.py` 用 ctypes 调 Windows 自带的 GDI+ 转一次格式。
2. **别去遍历 `GdipGetImageEncoders` 找 PNG 编码器**：`ImageCodecInfo` 结构体在不同位数下
   布局不一致，字段错一位就是进程级 segfault（实测崩过）。直接用 PNG 的固定 CLSID
   `{557CF406-1A04-11D3-9A73-0000F81EF32E}`。
3. **tk 没有圆角图片**。把方图裁成圆不能用 `create_arc(style="pieslice")` —— 扇形从圆心发出，
   四个 90° 拼起来正好是整个圆盘，会把头像整张盖住（第一版就是这么糊掉的）。
   正确做法是用四块「直角 + 圆弧」的 `create_polygon` 把四个角盖掉。
   另外 `tk.PhotoImage` 必须留引用（`self._avatar_photo = img`），否则被 GC 回收后显示白块。

拿不到头像（离线 / 被墙）时不会留空，会画一个绿底首字母圆形占位，功能不受影响。

### 发版：让「检测」有东西可比对

`build\release.py` 把发版三步串起来 —— 体检 → 打 tag 并推送 → 建 GitHub Release：

```powershell
python build\release.py --dry-run              # 只体检，不推不改
python build\release.py --notes-file notes.md  # 正式发（说明取自文件）
python build\release.py --version 1.6.0        # 顺手把 VERSION 改成 1.6.0 再发
python build\release.py --prerelease           # 发预发布版
```

体检会拦住三种常见事故：工作区有未提交改动、`VERSION` 与要发的版本不一致（只有 `--version` 改过才自动提交这一个文件）、
tag 已存在。令牌按 `GITHUB_TOKEN` 环境变量 → Windows 凭据管理器里的 git 令牌顺序取
（后者用 `git credential fill` 读，不落盘、不打印）。

> 本机 git 配的是 openssl 后端且缺 CA 链，`push` 会报 `unable to get local issuer certificate`。
> `release.py` 检测到这个错会**只对这一条命令**关掉校验重试一次，并明确打印出来，不动全局配置。

### 自动更新（真正把新版装上去）

`user\auto_update.py` 负责「装了它」：从 Release 下载签名好的 `.sys`，就地替换**正在运行**的那一份。

```powershell
python user\auto_update.py --check            # 只看有没有新版（等同 update_check）
python user\auto_update.py --apply --dry-run  # 打印计划，一个文件都不动
python user\auto_update.py --apply            # 只更新驱动
python user\auto_update.py --apply --all      # 驱动 + 用户层 py / README / VERSION
python user\auto_update.py --rollback         # 退回上一次更新前的驱动
python user\auto_update.py --status           # 当前版本、镜像路径与哈希、备份在哪
```

为什么不能「下载完直接覆盖」：驱动被 SCM 映射着，文件是占用的；而且本工程驱动默认带自锁，
`sc stop` 会被直接拒绝。所以顺序是固定的，每一步失败都能退回去：

```
1. 取 Release → 挑 .sys 资产 → 核对 SHA256SUMS      （不动任何东西）
2. 快照：防护开关 + 保护名单                          （驱动重启后是内存态，不存就丢）
3. 备份当前 .sys 到 build\backups\
4. 关自锁 → 下发卸载令牌 → 停服务（等到真的 STOPPED）
5. 覆盖镜像（重试 12 次，刚停的驱动要几百毫秒才放开文件）
6. 起服务 → 连设备 → 比对文件哈希 + 服务状态
7. 任一步失败：停 → 恢复备份 → 起服务 → 恢复开关，原样退回去
8. 成功：把防护开关和保护名单按第 2 步的快照恢复
```

几个刻意的取舍：

- **只换镜像，不动服务键**。`ImagePath`、`Start=2`、服务名都保持原样，所以开机自启不会因为更新而失效。
- **只更新运行时文件**（`user/*.py`、`README.md`、`VERSION`），不碰 `build/` 下的脚本和任何本地配置；
  每个被覆盖的文件先备份到 `build\backups\app-<时间>\`，内容相同则跳过（保留你的本地修改时间）。
- **更新前先松开自己**：界面触发更新时会把本地设备句柄关掉再起子进程，否则我们自己就占着设备。
- 更新完界面里那段代码还是内存里的旧版，**重启界面**才完全生效。

边界（别指望它做这些）：

- 新驱动必须**已经签好名**，且证书在本机受信任根里（自签名 + `testsigning on` 那条路）。
  签名不对 → 服务起不来 → 自动回滚，机器不会失去保护。
- 不做灰度、不校验签名链的吊销状态；这是本地演示工程，不是企业更新通道。
- 装机前请确认 `build\backups\` 所在磁盘有空间（每个备份约 12 KB，可以忽略，但别删了还指望 `--rollback`）。

> **实测踩到的一个坑**：本机装了正版火绒，驱动停下的瞬间，`HKLM\SYSTEM\CurrentControlSet\Services\sysguard`
> 会被顺手删掉（`sc start` 直接报 1060 服务不存在，4 次里能撞 3 次）。
> 所以更新流程在动手前会把服务注册参数（`ImagePath` / `Start` / `ErrorControl` / `Group`）记进
> `update_state.json`，启动时发现键没了就**按记录重建**再起。1.5.2 起才有这个自愈。


## 踩过的坑

**1. `ObRegisterCallbacks` 在 test signing 下直接返回 `STATUS_ACCESS_DENIED`**

即使 `testsigning on`、证书已导入受信任根、`sc start` 也能成功加载，注册回调依然会被拒。
原因是该 API 内部调用 `MmVerifyCallbackFunction`，检查调用者镜像 `LDR_DATA_TABLE_ENTRY->Flags`
里的“已通过有效签名”标记；而 Windows 在 test signing 模式下加载驱动后**不会**置这个标记。
这和 DSE（能否加载）是两道独立的门。

本工程在 `DriverEntry` 里调用 `ObRegisterCallbacks` 之前，把自己这一项的 `Flags |= 0x20`
（`LDRP_IMAGE_INTEGRITY_FORCED`）。**这是本地调试手段，正式发布必须换成真实 EV/WHQL 签名。**

**2. `DriverEntry` 失败会漏设备对象**

如果在 `IoCreateDevice` 之后、`DriverEntry` 返回之前失败，`\Device\sysguard` 会残留在对象管理器里，
而驱动镜像已经被卸载 —— 下一次加载撞名失败，而且那个空壳设备还能被 `CreateFile` 打开，
对它发 IOCTL 就是访问已卸载内存。因此驱动做了两件事：

- 设备名撞车时自动换成 `\Device\sysguard1..9`；
- 把实际使用的名字写进 `HKLM\SYSTEM\CurrentControlSet\Services\sysguard\Parameters\DeviceName`，
  用户态照着开，不会摸到空壳。

彻底清理残留仍然是重启最干净。

**3. 注册表回调用「对象指针相等」判断自己的服务键 —— 完全无效**

第一版是这么写的：

```c
if (target == g_ServiceKeyObject) return STATUS_ACCESS_DENIED;
```

`g_ServiceKeyObject` 是 `DriverEntry` 里 `ZwOpenKey` + `ObReferenceObjectByHandle` 拿到的对象。
**同一个注册表键可以有多个 key object**，SCM 删服务时用的那个对象和这里持有的不是同一个，
所以比对永远不成立。实测：`sc delete` 直接删掉服务、`SetValueEx` 改 `ImagePath` 畅通无阻，
而「删键被拒」其实是键下有子键时系统固有的行为，属于假阳性。

正确做法是用 `CmCallbackGetKeyObjectIDEx` 取对象**完整路径名**再比对后缀
（`\SERVICES\<服务名>`，大小写无关，兼容 `ControlSet001`）：

```c
status = CmCallbackGetKeyObjectIDEx(&cookie, Object, &id, &name, 0);
/* ... 比对 name->Buffer 尾部 ... */
CmCallbackReleaseKeyObjectIDEx(name);
```

注意通知结构里的 `Object` 有时是**非法的非 NULL 指针**，只能判空后交给这个 API，绝不自己解引用。
顺带一提：`DriverEntry` 里用 `RegistryPath` 推导服务键路径，换任何服务名都能自保护。

**4. `DeleteService` 返回 TRUE ≠ 服务被删掉**

注册表回调修好之后，测试里第 9 项仍然报"服务被成功删除"，但现场是：

```
服务状态 : RUNNING
注册表键 : Start=3，无 DeleteFlag
```

原因：SCM 先在**自己的内存数据库**里把服务标记为删除、直接给调用者返回
`TRUE`，随后才去写注册表（`DeleteFlag` / `Start=4`）。那一步被回调拒了，
它也不会改口。再调一次反而返回 `1072 (ERROR_SERVICE_MARKED_FOR_DELETE)`。

所以服务类测试的判据只能是**注册表键的真实内容**，不是 API 返回值。
同类教训在进程侧也有过一次：早期版本用 `OpenThread` 是否成功判断"能否挂起"，
而 Ob 回调只是把权限位清零、句柄照样能打开 —— 于是"突破"是假的，
改成真调 `SuspendThread` 之后才是 4/4 失败。

**5. 多实例并存时，测试会打到旧服务**

升级或换名安装（`-ServiceName sysguard2`）之后，机器上会同时留着旧服务。
旧版 `killtest.py` 的 `--service` 默认写死 `sysguard`，于是第 8–10 项打的是**旧服务**：

```
9  删除驱动服务   突破   服务已被标记删除（DeleteFlag=1, Start=4）
10 删除服务注册表键 突破   可以改写服务 ImagePath（注册表回调未生效）
```

看着像防护挂了，其实：旧键早就因为以前那次突破带着 `DeleteFlag=1`；而新驱动只保护
自己那个键（`\SERVICES\SYSGUARD2`），旧键当然能改。**结论被历史状态污染了。**

现在 `killtest.py` 用 `HKLM\SOFTWARE\SysGuard\ActiveDevice` 反查各服务的
`Parameters\DeviceName`，自动定位"活跃设备属于哪个服务"，`--service` 只作手动覆盖；
表头会打印被测服务与镜像路径。第 9 项还会先看测试前的状态，若键本来就被标记删除
就报"跳过（无法归因）"，而不是记成突破。

**6. `ImagePath` 里出现正斜杠 → 加载报「找不到文件」**

用 SCM API 装驱动时把路径写成 `\??\C:/Users/.../sysguard_v4.sys`，`sc start` 返回
**错误码 2**，而文件明明存在、权限也正常。注册表里读出来一眼就能看出来：

```
ImagePath = '\??\C:/Users/.../build/sysguard_v4.sys'   <- 正斜杠
```

内核加载器不接受正斜杠，把它改成 `\??\C:\Users\...` 后立刻 `StartService -> True`。
这也给当初那次「文件存在却报 2」提供了一个现成解释，以后遇到先看这一位。

**7. 构建环境**

Git Bash 会把 `/nologo` 这类参数当成路径，编译脚本必须用 `-` 前缀并设置 `MSYS2_ARG_CONV_EXCL="*"`，
路径用 `cygpath -m` 转成 `C:/...`。

**8. PowerShell 抓 Python 输出，中文全变乱码**

`install.ps1` 里 `& python ... 2>&1` 捕获子进程输出后，`[2/5]` 的 `已创建：Type=kernel`
显示成 `宸插垱寤猴細Type=kernel`。原因是 Python 3.15 起默认 UTF-8 输出（PEP 686），
而 PowerShell 5.1 解码原生命令输出用的是 OEM 代码页（这里 936）。

三种组合实测下来只有一种有效：

| 做法 | 结果 |
|---|---|
| 只设 `PYTHONIOENCODING=utf-8` | 仍乱码（Python 本来就在发 UTF-8） |
| 只设 `[Console]::OutputEncoding = UTF8` | 对，但直通控制台的调用会受影响 |
| **两者同时设，用完还原** | 对，且不影响后续输出 |

所以抽了个 `With-Utf8 { ... }`：进入时把两侧都钉到 UTF-8，`finally` 里还原
`[Console]::OutputEncoding` 与 `PYTHONIOENCODING`。`Invoke-Ctl` 和 `[4/5]` 的
`guard_ctl.py` 都走它——后者改成"捕获后 `Write-Host` 打印"，让 PowerShell 自己解码成
Unicode 字符串再输出，这样控制台是 936 还是 65001 都不影响。

顺带一句：`ps1` 文件本身必须纯 ASCII（中文注释在 PS 5.1 里会被当 GBK 解析，直接语法报错），
但 Python 打印的中文完全没问题，两件事别混。

**9. 把句柄当对象指针传给 `KeWaitForSingleObject` —— 两次蓝屏的真凶**

`GuardKillProcess` 里最初写的是：

```c
KeWaitForSingleObject(processHandle, Executive, KernelMode, FALSE, &timeout);  // 错
```

`KeWaitForSingleObject` 的第一个参数是「指向调度器对象的指针」
（`PKMUTANT` / `PDISPATCHER_HEADER`），**根本不接受句柄**。传进去的是句柄那种小整数，
内核会拿它当地址读 `[obj]`，并往 obj 的等待链表里插 —— 直接
`0x0000000A IRQL_NOT_LESS_OR_EQUAL`（写，IRQL 2，崩在 `lock bts [rdi],7`）。

正确写法是先换出真对象指针：

```c
PVOID obj = NULL;
ObReferenceObjectByHandle(processHandle, SYNCHRONIZE, NULL, KernelMode, &obj, NULL);
KeWaitForSingleObject(obj, Executive, KernelMode, FALSE, &timeout);
ObDereferenceObject(obj);
```

补充两点：`ZwWaitForSingleObject` 在 `wdm.h` 里**没有声明**（编译报 C4013），
别图省事直接调；另外 `KeWaitForSingleObject` 带超时时要求 IRQL ≤ APC_LEVEL，
放在 `IRP_MJ_DEVICE_CONTROL` 里是 PASSIVE_LEVEL，没问题。

这个 bug 的定位过程记在 `build\diag\dumpinfo.py` 的用法里：先看 BugCheck 参数，
再把出错指令反汇编出来认模式，最后在 dump 里搜落在驱动镜像地址范围内的返回值 ——
两次蓝屏在**同一文件偏移**命中了同一个 `call` 的返回地址，配合解析 PE 导入表
（IAT RVA → 函数名）就能钉死是哪个 API。

**10. 卸载驱动时释放保护名单，顺序写反了**

```c
for (entry = g_ProtectList.Flink; entry != &g_ProtectList; entry = entry->Flink) {
    ExFreePoolWithTag(CONTAINING_RECORD(entry, GUARD_PROTECT_ENTRY, ListEntry), GUARD_TAG);
}   // entry 自己刚被释放，entry->Flink 读的是已释放内存
```

`ListEntry` 是结构体首成员，`item == entry`。第一轮就把它释放掉，第二轮从已释放内存读
`Flink` —— 那块内存已被内存管理器改写成空闲链表链接，于是拿到野指针再交给
`ExFreePoolWithTag`，同样崩成 `0x0000000A`。**只要"卸载时保护名单非空"就必崩。**

改成先取后继再释放：

```c
entry = g_ProtectList.Flink;
while (entry != &g_ProtectList) {
    PGUARD_PROTECT_ENTRY item = CONTAINING_RECORD(entry, GUARD_PROTECT_ENTRY, ListEntry);
    entry = entry->Flink;              /* 先取后继 */
    ExFreePoolWithTag(item, GUARD_TAG);
}
```

两条经验：**链表遍历 + 释放一定要先存 next**；以及验收时必须专门测一次
「保护名单非空 → 卸载」，否则这条路径永远测不到。

**11. 旧实例没卸干净 → 界面「显示已连接」但新功能一律 `ERROR_INVALID_FUNCTION`**

现象很有欺骗性：状态栏绿灯「驱动已连接」，`query()` 也能返回数据，
可一调新加的 IOCTL 就 `[Errno 1] DeviceIoControl 失败`。

原因：`sysguard` 撞到设备名会自动换后缀（`\Device\sysguard1`…），于是**新旧两个版本
能同时驻留**，各自占一个设备名。用户态当时按「注册表里 ActiveDevice」优先打开，
而那个值是**最后加载的旧实例**写的 —— 于是连到 1.2 上，1.2 当然不认识 1.3 新增的 IOCTL。

排查一行就够：

```powershell
python build\diag\svc_probe.py
```

它会打印内核里实际加载了几个实例、每个设备背后的版本，以及 `Guard()` 会连到哪个。

修法是两层，都别省：

1. `Guard()` 打开时**把所有候选设备都试一遍，按驱动版本挑最高的**（`self.shadowed`
   保留被跳过的低版本实例，界面会因此提示"另有低版本实例在运行"）；
2. `detect_service_name()` 反查不到时，用**内核里真的加载了哪个 .sys** 去匹配各服务的
   `ImagePath`（只在名字含 `sysguard` 的服务里找，否则会把 `ACPI.sys` 认成自己的镜像）。

另外注意 `NtQuerySystemInformation(SystemModuleInformation)` 的结构体是
`RTL_PROCESS_MODULE_INFORMATION`（3 个指针 + `USHORT OffsetToFileName` + 256 字节路径，
共 296 字节），**不是** 5 个指针的 `LDR_DATA_TABLE_ENTRY`。写错会永远"查不到自己的驱动"，
从而误判成"驱动没驻留"。

**12. 驱动停止后，服务键有时会跟着消失；残留的设备符号链接让 `CreateFile` 返回 5 而不是 2**

实测四次，三次（`sysguard3`、`sysguard7`、`sysguard8`）在 `stop` 之后
`HKLM\SYSTEM\CurrentControlSet\Services\<名字>` 立刻就不存在了，一次（`sysguard`）保留了。
消失的那几次，系统日志里**一条 `7045/7040/7036` 服务变更事件都没有** —— 说明不是 SCM 的
正常删除流程（走 SCM 一定留事件）。这台机器上装着正版火绒且在运行，嫌疑最大，
但没有直接证据；而且它是间歇性的，所以先当作"外部干预"记着。

由此带来两个反直觉的现象，都会把排查带偏：

- `stop` 明明返回 `STOPPED`，紧接着 `key_state()` 却是 `None`，
  `service_state()` 也返回 `None`。**别把它当成 stop 失败** —— 是服务键已经没了。
  判活要看"设备能不能打开 + 内核模块表里有没有这个 .sys"，不要只看注册表。
- 驱动停止后 `\DosDevices\sysguard` 符号链接可能残留，此时
  `CreateFile("\\.\sysguard")` 返回 **5（拒绝访问）而不是 2（找不到）**。
  错误码 5 一向被解释成"没提权"，于是界面显示"请以管理员身份运行"，
  用户会去反复重装 —— 其实是"服务停了"。
  现在 `Guard.__init__` 失败时会顺带查服务状态，追加一句
  「服务 sysguard8 当前是 STOPPED，先启动它」；GUI 也改成按**服务状态**
  决定要不要自动拉起，而不是靠错误码。

对策是把 `make_autostart.py` 做成幂等的：已经配好就不停机，减少这个窗口。

## 加载失败怎么查

`sc start` 返回的错误码只说明结果，不说明原因。工程里带了一套对照实验：

```powershell
powershell -ExecutionPolicy Bypass -File build\loadtest.ps1
```

它会按顺序试几种组合，**命中即停**：

| 步骤 | 镜像 | 位置 |
|---|---|---|
| 1 | `probe.sys`（只写一个标记，不创建设备、不注册回调） | 工程 build 目录 |
| 2 | `probe.sys` | `System32\drivers` |
| 3 | `sysguard.sys`（带 LDR 补丁） | 工程 build 目录 |
| 4 | `sysguard.sys` | `System32\drivers` |
| 5 | `sysguard_np.sys`（不带 LDR 补丁） | 工程 build 目录 |

结果怎么读：

- **1 成功、3 失败、5 也失败** → 机器接受自定义驱动，是 `sysguard` 整体内容被拒；
- **1 成功、3 失败、5 成功** → 被拒的是那段 LDR 标志位补丁；
- **1 和 2 都失败** → 连空驱动都加载不了，问题在机器策略/安全软件层，与驱动代码无关；
- **3 或 4 成功** → 已加载，直接开界面。

探针是否真的执行过，看 `HKLM\SOFTWARE\SysGuardProbe` 下的 `Entered` 值。

构建两个版本：

```bash
bash build/build.sh sysguard                                  # 带 LDR 补丁
bash build/build.sh sysguard sysguard_np -DSG_NO_LDR_PATCH    # 不带
powershell -File build\sign.ps1 -Name sysguard_np
```

### 错误码对照（看 `[diag] breadcrumb` 那行）

| status | 含义 | 处理 |
|---|---|---|
| 没有 breadcrumb | 镜像没跑起来就被拒 | 机器策略层，与代码无关 |
| `0xC0000022` | `ObRegisterCallbacks` 权限被拒（test signing 未通过回调校验） | 保留 LDR 补丁分支 |
| `0xC01C0011` | **altitude 撞车**：该值已被别的组件占用 | 驱动已内置探测，无需处理 |
| `0xC0000034` / `2` | 找不到镜像 | 检查 ImagePath |

altitude 是 `ObRegisterCallbacks` / `CmRegisterCallbackEx` 的排序键，**全系统唯一**。
`320000` 是教程里最常见的默认值，也是各种 HIPS 自保护抢着用的值，撞上就加载失败。
现在驱动从 `349000` 起逐个试（最多 32 个），实际使用的值写在
`HKLM\SYSTEM\CurrentControlSet\Services\sysguard\Parameters\Altitude`。

### 界面显示「驱动未加载 / [Errno 433]」

先分清是**没提权**还是**真没装**：

```powershell
python user\guard_ctl.py      # 失败时会逐个候选试开并打印真实错误码
```

| 报错 | 真实原因 | 处理 |
|---|---|---|
| `错误 5` | 进程没提升为管理员。设备 DACL 只给 Administrators 全权，**Everyone 连读都没有** | 正常情况下入口会自己弹 UAC；如果 UAC 被取消，用「以管理员身份运行」重开即可 |
| `错误 32` | 设备已被别的进程独占打开 | 关掉另一个界面 / 测试进程 |
| `错误 2 / 433` | 驱动确实没装或没启动 | 跑 `build\install.ps1` |

> 早期版本这里一定会显示 433：`Guard` 取的是候选列表**最后一个**的错误码，而末位是
> `\\.\sysguard`（本机通常不存在），于是把真正的 `5` 盖掉了。现在按「信息量」挑错误，
> 忽略 2/3/433 这类只说明"名字不存在"的噪音码，前面还会附上实际尝试过的候选。

## 已知边界（这不是完整的安全产品）

- 保护名单按 **PID** 记录，进程退出后条目不会自动清理，PID 复用会有误保护。
- 驱动自身没有 PE 签名加固、没有反调试、没有对 `\Device\sysguard` 的 ACL 加固；
  真火绒还有 minifilter、ETW 消费、云查杀、进程树回溯等一整套。
- 本工程用于**自己的驱动/软件做防护强度验证**，不要拿去做绕过他人安全软件的工具。
- 内核驱动以 SYSTEM 权限运行，一个空指针就是蓝屏。改代码前先想清楚 IRQL 和锁。

## 环境

- Windows 10/11 x64，`testsigning on`（本机已开启）
- WDK 10.0.26100 + VS2022 (MSVC 14.44)
- Python 3.8+（界面只用标准库）
