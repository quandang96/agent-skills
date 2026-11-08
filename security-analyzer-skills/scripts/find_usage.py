#!/usr/bin/env python3
"""
Xác định mức bằng chứng về phạm vi ảnh hưởng cho từng thư viện trong analysis.json.

  python find_usage.py analysis.json --src <repo_dir> [--src <dir2>] [--govulncheck govuln.json]

Ba mức (ghi vào findings[].usage.level):
  1. "Dependency"  - chỉ biết package có trong dependency/SBOM (mặc định)
  2. "Import"      - tìm thấy import/require (hoặc khai báo plugin trong file config) trong source
  3. "Reachable"   - công cụ phân tích đường gọi (govulncheck cho Go) xác nhận code gọi tới hàm bị lỗi

Giới hạn (ghi rõ trong kết quả):
  - Tìm bằng regex: có thể sót dynamic import với tên tính toán, plugin tự nạp, reflection.
    "Không tìm thấy import" KHÔNG chứng minh CVE không khai thác được.
  - Có import chưa chứng minh có gọi hàm bị lỗi.
  - Thư viện transitive: tìm thư viện direct kéo nó vào → chỉ xác nhận một phần đường phụ thuộc.
"""
import argparse
import json
import os
import re
from collections import Counter

SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".nuxt", ".output", ".next", "vendor", "target",
             "__pycache__", ".venv", "venv", "coverage", ".cache", "out", ".gradle", ".idea", ".svelte-kit"}
EXT = {
    "npm": (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".vue", ".svelte", ".astro"),
    "golang": (".go",),
    "pypi": (".py",),
    "maven": (".java", ".kt", ".kts", ".scala", ".groovy"),
}
# file config nơi plugin/module được khai báo bằng chuỗi (không có import)
CONFIG_RE = {
    "npm": re.compile(r"(^|/)(nuxt|vite|webpack|rollup|babel|next|vue|svelte|astro|jest|vitest|eslint|postcss|tailwind)"
                      r"\.config\.[cm]?[jt]s$|(^|/)\.babelrc(\.json)?$|(^|/)\.eslintrc(\.\w+)?$"),
    "pypi": re.compile(r"(^|/)(settings|conf|config)\.py$"),
}
DYNAMIC_RE = {
    "npm": re.compile(r"(?:require|import)\(\s*(?!['\"`])[\w.$\[\]]+"),
    "pypi": re.compile(r"(?:importlib\.import_module|__import__)\(\s*(?!['\"])"),
}
PY_IMPORT_ALIASES = {"pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "PIL", "scikit-learn": "sklearn",
                     "python-dateutil": "dateutil", "pyjwt": "jwt", "opencv-python": "cv2", "protobuf": "google.protobuf",
                     "python-jose": "jose", "pycryptodome": "Crypto", "psycopg2-binary": "psycopg2"}
LEVEL_RANK = {"Dependency": 1, "Import": 2, "Reachable": 3}


def import_pattern(eco, name):
    if eco == "npm":
        n = re.escape(name)
        return re.compile(rf"""(?:require(?:\.resolve)?\(\s*|import\(\s*|from\s+|import\s+|export\s+\*\s+from\s+)['"`]{n}(?:/[^'"`]*)?['"`]""")
    if eco == "golang":
        return re.compile(rf'"{re.escape(name)}(?:/[^"]*)?"')
    if eco == "pypi":
        mod = PY_IMPORT_ALIASES.get(name.lower(), name.replace("-", "_"))
        return re.compile(rf"^\s*(?:import|from)\s+{re.escape(mod)}\b|import_module\(\s*['\"]{re.escape(mod)}", re.M | re.I)
    if eco == "maven":
        group = name.split(":")[0]
        return re.compile(rf"^\s*import\s+(?:static\s+)?{re.escape(group)}\.", re.M)
    return None


def config_pattern(eco, name):
    if eco not in CONFIG_RE:
        return None
    return re.compile(rf"""['"`]{re.escape(name)}(?:/[^'"`]*)?['"`]""")


MAX_FILE = 2 * 1024 * 1024  # bỏ qua file > 2MB (bundle/minified, dữ liệu)


def walk(roots):
    """Chỉ đọc file thật nằm trong repo: không theo symlink (file hay thư mục), bỏ file quá lớn."""
    for root in roots:
        real_root = os.path.realpath(root)
        for d, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not x.startswith(".")
                       and not os.path.islink(os.path.join(d, x))]
            for fn in files:
                p = os.path.join(d, fn)
                if os.path.islink(p) or not os.path.realpath(p).startswith(real_root + os.sep):
                    continue
                try:
                    if os.path.getsize(p) > MAX_FILE:
                        continue
                except OSError:
                    continue
                yield p


def module_of(path, root):
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    parts = rel.split("/")
    return "/".join(parts[:2]) if len(parts) > 2 else parts[0]


def read_text(path):
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return fh.read()


def parse_govulncheck(path):
    """govulncheck -json: luồng các object JSON. Trả về {vuln_id/alias: {"module", "level", "symbols"}}."""
    text = read_text(path)
    dec, i, objs = json.JSONDecoder(), 0, []
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        obj, i = dec.raw_decode(text, i)
        objs.append(obj)
    aliases, res = {}, {}
    for o in objs:
        if "osv" in o and isinstance(o["osv"], dict):
            aliases[o["osv"]["id"]] = o["osv"].get("aliases", [])
    for o in objs:
        fd = o.get("finding")
        if not fd or not fd.get("trace"):
            continue
        top = fd["trace"][0]
        level = "Reachable" if top.get("function") else "Import" if top.get("package") else "Dependency"
        sym = f"{top.get('package', '')}.{top.get('function')}" if top.get("function") else None
        for vid in [fd["osv"]] + aliases.get(fd["osv"], []):
            cur = res.setdefault(vid.upper(), {"module": top.get("module"), "level": "Dependency", "symbols": []})
            if LEVEL_RANK[level] > LEVEL_RANK[cur["level"]]:
                cur["level"] = level
            if sym and sym not in cur["symbols"]:
                cur["symbols"].append(sym)
    return res


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("analysis")
    ap.add_argument("--src", action="append", default=[])
    ap.add_argument("--govulncheck", help="output của: govulncheck -json ./...")
    ap.add_argument("--max-sample", type=int, default=5)
    a = ap.parse_args(argv)
    data = json.loads(read_text(a.analysis))
    if not a.src and not a.govulncheck:
        ap.error("cần --src và/hoặc --govulncheck")

    # ---- tên cần tìm cho từng finding
    targets = {}
    for f in data["findings"]:
        if f.get("kind") != "app" or f.get("ecosystem") not in EXT:
            continue
        sb = f.get("sbom") or {}
        transitive = f.get("relation") == "transitive" or sb.get("relation_sbom") == "transitive"
        names = (sb.get("via_direct") or [f["name"]]) if transitive else [f["name"]]
        f["_search"] = (names, transitive)
        for n in names:
            targets.setdefault((f["ecosystem"], n), {"import": [], "config": []})

    # ---- quét source
    dynamic = Counter()
    files_scanned = 0
    if a.src:
        ipat = {k: import_pattern(*k) for k in targets}
        cpat = {k: config_pattern(*k) for k in targets}
        for path in walk(a.src):
            rel = path.replace(os.sep, "/")
            for eco in {k[0] for k in targets} | set(DYNAMIC_RE):
                is_src = path.endswith(EXT.get(eco, ()))
                is_cfg = bool(CONFIG_RE.get(eco) and CONFIG_RE[eco].search(rel))
                if not (is_src or is_cfg):
                    continue
                try:
                    text = read_text(path)
                except OSError:
                    continue
                files_scanned += 1
                if eco in DYNAMIC_RE and DYNAMIC_RE[eco].search(text):
                    dynamic[eco] += 1
                for (e, n), hits in targets.items():
                    if e != eco:
                        continue
                    if is_src and ipat[(e, n)] and ipat[(e, n)].search(text):
                        hits["import"].append(path)
                    elif is_cfg and cpat[(e, n)] and cpat[(e, n)].search(text):
                        hits["config"].append(path)

    gv = parse_govulncheck(a.govulncheck) if a.govulncheck else {}

    root0 = a.src[0] if a.src else "."
    for f in data["findings"]:
        names_t = f.pop("_search", None)
        u = {"level": "Dependency" if f.get("join") == "sbom" else "Không rõ", "searched": None, "files": 0,
             "modules": [], "sample": [], "via_parent": False, "reachable_symbols": [], "limits": []}
        if names_t and a.src:
            names, transitive = names_t
            imp = sorted({p for n in names for p in targets[(f["ecosystem"], n)]["import"]})
            cfg = sorted({p for n in names for p in targets[(f["ecosystem"], n)]["config"]})
            allf = imp + [c for c in cfg if c not in imp]
            mods = Counter(module_of(p, root0) for p in allf)
            u.update({"searched": ", ".join(names), "files": len(allf), "via_parent": transitive,
                      "modules": [f"{m} ({c})" for m, c in mods.most_common(5)],
                      "sample": [os.path.relpath(p, root0) for p in allf[:a.max_sample]],
                      "config_only": bool(cfg) and not imp})
            if allf:
                u["level"] = "Import"
            else:
                u["limits"].append("Không tìm thấy import - không loại trừ dynamic import/plugin; không chứng minh CVE không khai thác được")
            if transitive:
                u["limits"].append("Transitive: chỉ xác nhận có dùng thư viện cha, chưa chứng minh gọi tới thư viện này")
            if dynamic.get(f["ecosystem"]):
                u["limits"].append(f"Có {dynamic[f['ecosystem']]} file dùng dynamic import/require với tên tính toán - regex không phân tích được")
        if f.get("ecosystem") == "golang" and gv:
            ids = {v["id"].upper() for v in f.get("vulns", [])} | {x.upper() for v in f.get("vulns", []) for x in v.get("aliases", [])}
            hits = [gv[i] for i in ids if i in gv]
            for v in f.get("vulns", []):
                r = gv.get(v["id"].upper()) or next((gv[x.upper()] for x in v.get("aliases", []) if x.upper() in gv), None)
                if r:
                    v["reachability"] = r["level"]
            if hits:
                best = max(hits, key=lambda h: LEVEL_RANK[h["level"]])
                if LEVEL_RANK[best["level"]] >= LEVEL_RANK.get(u["level"], 0):
                    u["level"] = best["level"]
                u["reachable_symbols"] = sorted({s for h in hits for s in h["symbols"]})[:5]
                u["reachability_tool"] = "govulncheck"
            elif ids:
                u["limits"].append("govulncheck không báo CVE này được gọi tới (kiểm tra govulncheck đã chạy trên đúng module)")
        elif f.get("kind") == "app" and f.get("vulns"):
            u["limits"].append("Chưa phân tích reachability (chỉ có cho Go qua govulncheck)")
        f["usage"] = u

    data["meta"].setdefault("coverage", {}).setdefault("sources", {})["source_code"] = bool(a.src)
    if gv:
        data["meta"]["coverage"]["sources"]["reachability"] = "govulncheck"
    data["meta"]["usage_scan"] = {"files_scanned": files_scanned, "dynamic_import_files": dict(dynamic)}
    with open(a.analysis, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1)

    for f in data["findings"]:
        u = f["usage"]
        if u["searched"] or u["reachable_symbols"]:
            print(f"{f['name']}@{f['version']}: {u['level']}" + (f" qua [{u['searched']}]" if u["via_parent"] else "")
                  + f" - {u['files']} file" + (f" | {', '.join(u['modules'])}" if u["modules"] else "")
                  + (f" | gọi: {', '.join(u['reachable_symbols'])}" if u["reachable_symbols"] else ""))
    if dynamic:
        print(f"⚠ dynamic import với tên tính toán: {dict(dynamic)} file")
    print(f"→ Đã cập nhật {a.analysis}")
    return data


if __name__ == "__main__":
    main()
