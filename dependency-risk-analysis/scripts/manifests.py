"""
Đọc manifest của project để nhận diện **package gốc** (chính project đang quét, không phải dependency).

Chỉ đọc tên project/workspace - KHÔNG dùng manifest/lockfile để suy ra version đang chạy trong image.
An toàn: không theo symlink, bỏ qua file > 1MB, chỉ đọc file trong thư mục được chỉ định và workspace con.
"""
import glob
import json
import os
import re

MAX_MANIFEST = 1024 * 1024


def _read(path):
    if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > MAX_MANIFEST:
        return None
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return fh.read()


def _inside(path, root):
    return os.path.realpath(path).startswith(os.path.realpath(root) + os.sep) or os.path.realpath(path) == os.path.realpath(root)


def _npm(d, root, out, depth=0):
    text = _read(os.path.join(d, "package.json"))
    if not text:
        return
    try:
        pj = json.loads(text)
    except ValueError:
        return
    if pj.get("name"):
        out.append({"eco": "npm", "name": pj["name"], "private": bool(pj.get("private")),
                    "manifest": os.path.relpath(os.path.join(d, "package.json"), root)})
    ws = pj.get("workspaces")
    ws = ws.get("packages", []) if isinstance(ws, dict) else ws or []
    if depth == 0:
        for pat in ws[:50]:
            for sub in sorted(glob.glob(os.path.join(d, pat)))[:200]:
                if os.path.isdir(sub) and not os.path.islink(sub) and _inside(sub, root):
                    _npm(sub, root, out, depth + 1)


def _go(d, root, out):
    text = _read(os.path.join(d, "go.mod"))
    m = re.search(r"^module\s+(\S+)", text or "", re.M)
    if m:
        out.append({"eco": "golang", "name": m.group(1), "private": None, "manifest": os.path.relpath(os.path.join(d, "go.mod"), root)})


def _py(d, root, out):
    text = _read(os.path.join(d, "pyproject.toml"))
    if text:
        m = re.search(r"^\[(?:project|tool\.poetry)\][^\[]*?^name\s*=\s*['\"]([^'\"]+)['\"]", text, re.M | re.S)
        if m:
            out.append({"eco": "pypi", "name": m.group(1), "private": None, "manifest": os.path.relpath(os.path.join(d, "pyproject.toml"), root)})


def _maven(d, root, out):
    text = _read(os.path.join(d, "pom.xml"))
    if not text:
        return
    body = re.sub(r"<parent>.*?</parent>|<dependencies>.*|<build>.*|<!--.*?-->", "", text, flags=re.S)
    g, a = re.search(r"<groupId>\s*([^<\s]+)", body), re.search(r"<artifactId>\s*([^<\s]+)", body)
    if not g:
        g = re.search(r"<parent>.*?<groupId>\s*([^<\s]+)", text, re.S)
    if g and a:
        out.append({"eco": "maven", "name": f"{g.group(1)}:{a.group(1)}", "private": None, "manifest": os.path.relpath(os.path.join(d, "pom.xml"), root)})


def _composer(d, root, out):
    text = _read(os.path.join(d, "composer.json"))
    try:
        name = json.loads(text).get("name") if text else None
    except ValueError:
        name = None
    if name:
        out.append({"eco": "composer", "name": name, "private": None, "manifest": os.path.relpath(os.path.join(d, "composer.json"), root)})


def project_roots(dirs):
    """-> danh sách {eco, name, private, manifest} của project gốc và workspace."""
    out = []
    for d in dirs or []:
        if not os.path.isdir(d):
            continue
        for fn in (_go, _py, _maven, _composer):
            fn(d, d, out)
        _npm(d, d, out)
    seen, res = set(), []
    for r in out:
        k = (r["eco"], r["name"].lower())
        if k not in seen:
            seen.add(k)
            res.append(r)
    return res
