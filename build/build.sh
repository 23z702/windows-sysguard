#!/bin/bash
# 编译内核驱动：build.sh [name]   默认 sysguard
# 直接调用 MSVC + WDK，不依赖 MSBuild
# 注意：Git Bash 会把 /xxx 参数当成路径，因此全部使用 - 前缀并关闭参数转换
set -e
export MSYS2_ARG_CONV_EXCL="*"

NAME="${1:-sysguard}"
OUTNAME="${2:-$NAME}"
EXTRA_DEFS="$3"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cygpath -m "$ROOT")"   # 转成 Windows 风格 C:/... 给 cl/link 用
WDK_INC="C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0"
WDK_LIB="C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0/km/x64"
MSVC="C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207"

export INCLUDE="$WDK_INC/km;$WDK_INC/km/crt;$WDK_INC/shared;$MSVC/include"
export LIB="$WDK_LIB;$MSVC/lib/x64"

CL="$MSVC/bin/Hostx64/x64/cl.exe"
LINK="$MSVC/bin/Hostx64/x64/link.exe"

OUT="$ROOT/build"
mkdir -p "$OUT/obj"

DEFS="-D_AMD64_ -D_M_AMD64 -D_WIN32_WINNT=0x0A00 -DNTDDI_VERSION=0x0A000000 -DDBG=0 -DUNICODE -D_UNICODE $EXTRA_DEFS"

echo "==> 编译 $NAME.c  ->  $OUTNAME.sys"
"$CL" -nologo -c -O1 -Os -GS- -Gm- -Gy -Zp8 -W3 -WX- -utf-8 -kernel \
    $DEFS -Fo"$OUT/obj/$OUTNAME.obj" "$ROOT/driver/$NAME.c"

echo "==> 链接 $OUTNAME.sys"
"$LINK" -nologo -DRIVER -SUBSYSTEM:NATIVE -MACHINE:X64 -ENTRY:DriverEntry \
    -OUT:"$OUT/$OUTNAME.sys" -NODEFAULTLIB:libcntpr.lib \
    "$OUT/obj/$OUTNAME.obj" \
    ntoskrnl.lib hal.lib wdm.lib BufferOverflowK.lib

echo "==> 生成完毕"
ls -l "$OUT/$OUTNAME.sys"
