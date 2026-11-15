"""release.py —— 发版：打 tag + 建 GitHub Release（给 update_check.py 提供比对目标）

update_check.py 只看 GitHub 的 Release/Tag，所以「有新版本」这件事需要先把版本发出去。
这个脚本把发版的三步串起来，避免手抖：

    1. 校验 VERSION 与工作区（必须干净、tag 不能重复）
    2. git tag v1.5.0 + push main 和 tag
    3. POST /repos/{repo}/releases 建 Release（说明取自 --notes-file 或最近提交）

令牌来源（按顺序）：环境变量 GITHUB_TOKEN/GH_TOKEN -> Windows 凭据管理器里的 git 令牌
（用 `git credential fill` 读，不落盘、不打印）。

用法：
    python build\\release.py --dry-run                 # 只体检，不推不改
    python build\\release.py --notes-file notes.md     # 正式发版
    python build\\release.py --version 1.6.0           # 顺便把 VERSION 改成 1.6.0 再发
    python build\\release.py --prerelease              # 发预发布版

前置：新增/修改的文件要**先自己 commit**，本脚本只在 --version 改过 VERSION 时替你提交这一个文件。
"""

import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

REPO = "23z702/windows-sysguard"
API = "https://api.github.com"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION_FILE = os.path.join(ROOT, "VERSION")


def sh(*args, check=True, timeout=120, env=None):
    """跑一条命令，返回 CompletedProcess（stdout/stderr 都是 str）。"""
    p = subprocess.run(["git"] + list(args), cwd=ROOT, text=True,
                       encoding="utf-8", errors="replace",
                       capture_output=True, timeout=timeout, env=env)
    if check and p.returncode != 0:
        raise SystemExit("[FAIL] git %s\n%s" % (" ".join(args),
                                                (p.stderr or p.stdout).strip()))
    return p


def git_out(*args):
    return sh(*args).stdout.strip()


def read_version():
    try:
        with open(VERSION_FILE, "r", encoding="utf-8") as f:
            return f.read().strip().lstrip("vV")
    except OSError:
        raise SystemExit("[FAIL] 找不到 VERSION 文件：%s" % VERSION_FILE)


def write_version(v):
    with open(VERSION_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(v + "\n")


def token():
    for k in ("GITHUB_TOKEN", "GH_TOKEN", "SYGUARD_GITHUB_TOKEN"):
        v = os.environ.get(k)
        if v and v.strip():
            return v.strip(), k
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    p = subprocess.run(["git", "credential", "fill"], cwd=ROOT, text=True,
                       input="protocol=https\nhost=github.com\n\n",
                       capture_output=True, env=env, timeout=60)
    for line in p.stdout.splitlines():
        if line.startswith("password="):
            return line[len("password="):].strip(), "git credential"
    return None, None


def push_with_ssl_fallback(*args):
    """先按正常校验推；本机 git 用 openssl 后端找不到 CA 时，退到不校验再推一次。

    只在这条命令上关校验，不改全局配置；失败原因会原样打印，不吞。
    """
    p = sh(*args, check=False)
    if p.returncode == 0:
        return True
    msg = (p.stderr or "") + (p.stdout or "")
    if "unable to get local issuer certificate" in msg or "SSL certificate" in msg:
        print("  [i] 本机 git 的 CA 链不可用，单次关闭校验重试 push")
        p = sh("-c", "http.sslVerify=false", *args, check=False)
        if p.returncode == 0:
            return True
    print("[FAIL] git %s\n%s" % (" ".join(args), msg.strip()))
    return False


def api(method, path, payload=None, tok=None):
    url = API + path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "User-Agent": "sysguard-release/1.0",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": "Bearer " + tok,
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, (json.loads(r.read().decode("utf-8")) or None)
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {}
        return e.code, body


def default_notes(prev_tag):
    rng = "%s..HEAD" % prev_tag if prev_tag else "HEAD"
    log = sh("log", "--no-merges", "--pretty=format:- %s", rng).stdout.strip()
    return "## 变更\n\n" + (log or "- （无提交记录）") + "\n"


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def upload_asset(upload_url, path, tok, label=None):
    """把文件传到 Release 的 assets（GitHub 用 raw body，不需要 multipart）。"""
    name = os.path.basename(path)
    base = upload_url.split("{")[0]
    q = {"name": name}
    if label:
        q["label"] = label
    url = base + "?" + urllib.parse.urlencode(q)

    with open(path, "rb") as f:
        payload = f.read()

    req = urllib.request.Request(url, data=payload, method="POST", headers={
        "User-Agent": "sysguard-release/1.0",
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + tok,
        "Content-Type": "application/octet-stream",
    })
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {}
        return e.code, body


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    dry = "--dry-run" in argv
    prerelease = "--prerelease" in argv
    ver = None
    notes_file = None
    assets = []
    for i, a in enumerate(argv):
        if a == "--version" and i + 1 < len(argv):
            ver = argv[i + 1].lstrip("vV")
        if a == "--notes-file" and i + 1 < len(argv):
            notes_file = argv[i + 1]
        if a == "--asset" and i + 1 < len(argv):
            assets.append(argv[i + 1])

    ver = ver or read_version()

    print("仓库      : %s" % REPO)
    print("发布版本  : %s" % ver)
    print("tag       : v%s" % ver)

    # ---- 1. 体检 ----
    if sh("rev-parse", "--is-inside-work-tree", check=False).returncode != 0:
        raise SystemExit("[FAIL] 当前目录不是 git 仓库")

    cur = read_version()
    if ver != cur:
        print("VERSION   : %s -> %s（发版时会一并提交）" % (cur, ver))

    dirty = git_out("status", "--porcelain")
    if dirty and ver == cur:
        print("\n[!] 工作区有未提交的改动，先 commit 完再发版：")
        print("\n".join("    " + l for l in dirty.splitlines()[:15]))
        raise SystemExit("[FAIL] 工作区不干净")
    if dirty and ver != cur:
        print("[i] 工作区有未提交改动，本脚本只提交 VERSION 这一个文件，其余请自行处理")

    tag = "v" + ver
    if sh("rev-parse", "-q", "--verify", "refs/tags/" + tag, check=False).returncode == 0:
        raise SystemExit("[FAIL] tag %s 已存在。改 VERSION 后再发，或用 git tag -d 删掉重来" % tag)

    if dry:
        print("\n[dry-run] 将要执行：")
        print("    git add VERSION && git commit")
        print("    git tag -a %s" % tag)
        print("    git push origin main && git push origin %s" % tag)
        print("    POST /repos/%s/releases" % REPO)
        for a in assets:
            if not os.path.isfile(a):
                raise SystemExit("[FAIL] 资产不存在：%s" % a)
            print("    上传资产 %s  (sha256=%s…)" % (a, sha256_of(a)[:16]))
        if assets:
            print("    上传 SHA256SUMS.txt（自动生成，供自动更新校验完整性）")
        return 0

    # ---- 2. 改版本 -> 提交 -> 打 tag -> 推 ----
    if ver != cur:
        write_version(ver)
        sh("add", "VERSION")
        sh("-c", "core.autocrlf=false", "commit", "-m", "release: v%s" % ver)

    sh("tag", "-a", tag, "-m", "sysguard v%s" % ver)
    print("\n[1/3] 打 tag %s 完成" % tag)

    if not push_with_ssl_fallback("push", "origin", "HEAD:main"):
        raise SystemExit("[FAIL] 推送 main 失败")
    if not push_with_ssl_fallback("push", "origin", tag):
        raise SystemExit("[FAIL] 推送 tag 失败")
    print("[2/3] 推送 main + %s 完成" % tag)

    # ---- 3. 建 Release ----
    tok, src = token()
    if not tok:
        raise SystemExit("[FAIL] 没有可用令牌：设置 GITHUB_TOKEN 环境变量，"
                         "或先随便 push 一次让 git 凭据管理器登录 GitHub")
    print("[i] 令牌来源：%s" % src)

    if notes_file:
        with open(notes_file, "r", encoding="utf-8") as f:
            notes = f.read()
    else:
        prev = sh("describe", "--tags", "--abbrev=0", tag + "^", check=False).stdout.strip()
        notes = default_notes(prev or None)

    st, body = api("POST", "/repos/%s/releases" % REPO, {
        "tag_name": tag,
        "name": "sysguard v%s" % ver,
        "body": notes,
        "draft": False,
        "prerelease": bool(prerelease),
    }, tok)

    if st in (200, 201) and isinstance(body, dict):
        print("[3/3] Release 已创建：%s" % body.get("html_url"))

        if assets:
            up = body.get("upload_url", "")
            sums_path = os.path.join(ROOT, "build", "SHA256SUMS.txt")
            lines = []
            ok_all = True
            for a in assets:
                if not os.path.isfile(a):
                    print("[FAIL] 资产不存在：%s" % a)
                    ok_all = False
                    continue
                digest = sha256_of(a)
                lines.append("%s  %s" % (digest, os.path.basename(a)))
                code, r = upload_asset(up, a, tok)
                if code in (200, 201):
                    print("  [asset] %-28s %s" % (os.path.basename(a),
                                                  "%.1f MB" % (os.path.getsize(a) / 1048576)))
                else:
                    ok_all = False
                    print("  [FAIL] 上传 %s 失败 HTTP %s：%s"
                          % (os.path.basename(a), code, (r or {}).get("message")))

            # 校验清单最后传：自动更新先拉它，再核对 .sys 的 sha256
            with open(sums_path, "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(lines) + "\n")
            code, _ = upload_asset(up, sums_path, tok)
            print("  [asset] SHA256SUMS.txt             %s" % ("ok" if code in (200, 201)
                                                             else "FAIL HTTP %s" % code))
            print("\n资产清单：")
            for line in lines:
                print("    " + line)
            if not ok_all:
                print("\n[!] 有资产没传成功，自动更新会退回「只更新用户层」。"
                      "到 Release 页面手动补传即可。")

        print("\n验证： python user\\update_check.py --force")
        return 0

    if st == 422:
        print("[FAIL] GitHub 说这个 tag 已经有 Release 了：%s" % (body or {}).get("message"))
        return 1
    print("[FAIL] 建 Release 失败 HTTP %s：%s" % (st, (body or {}).get("message", body)))
    print("       tag 已经推上去了，修好权限后可只补 Release：")
    print("       https://github.com/%s/releases/new?tag=%s" % (REPO, tag))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
