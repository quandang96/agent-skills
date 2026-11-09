#!/usr/bin/env python3
"""
Gộp Trivy + Uzomuzo + SBOM (SPDX JSON) thành analysis.json theo từng thư viện.

  python3 aggregate.py --trivy trivy.json [--trivy trivy-native.json] --uzomuzo uzomuzo-report.json \
      --sbom app-sbom.json [--kev kev.json] [--epss epss.csv[.gz]] [--osv | --online] -o analysis.json

  --trivy   issue list (GitLab code-quality, root là mảng) hoặc Trivy JSON gốc (root có "Results"); lặp được
  --kev     CISA KEV catalog JSON (known_exploited_vulnerabilities.json)
  --epss    EPSS CSV (cve,epss,percentile), có thể .gz
  --osv     tra api.osv.dev: bản vá + khoảng version bị ảnh hưởng (cần mạng)
  --online  = --osv + tải KEV + EPSS API + endoflife.date (cần mạng; lỗi mạng thì bỏ qua và ghi vào coverage)
  --project DIR        đọc manifest (package.json/go.mod/...) chỉ để nhận diện project gốc; --root-package NAME
  --deployed-digest    digest image đang chạy → đối chiếu Trivy ↔ SBOM ↔ deployment (trạng thái Verified/Preliminary)

Nguyên tắc: không kết luận "an toàn" khi thiếu nguồn dữ liệu; mọi giới hạn được ghi vào meta.coverage.
"""
import argparse
import csv
import datetime as dt
import fnmatch
import gzip
import io
import json
import os
import re
import sys
import urllib.request
from collections import defaultdict, deque
from urllib.parse import unquote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import manifests as M  # noqa: E402
import versions as V  # noqa: E402

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
SEV_BASE = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "UNKNOWN": 0}
CQ_TO_SEV = {"blocker": "CRITICAL", "critical": "CRITICAL", "major": "HIGH", "minor": "MEDIUM", "info": "LOW"}
VULN_ID_RE = re.compile(
    r"\b(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|GO-\d{4}-\d+|PYSEC-\d{4}-\d+|"
    r"RUSTSEC-\d{4}-\d+|DLA-\d+-\d+|DSA-\d+-\d+|ALAS\d*-\d{4}-\d+|RHSA-\d{4}:\d+|USN-\d+-\d+)\b", re.I)
OS_TYPES = {"deb", "rpm", "apk", "alpm"}
OS_TARGET_RE = re.compile(r"\((debian|ubuntu|alpine|rhel|redhat|centos|amazon|rocky|alma|oracle|photon|wolfi|"
                          r"chainguard|suse|opensuse|mariner|azurelinux|fedora)[^)]*\)", re.I)
ROOT_PURPOSES = {"APPLICATION", "CONTAINER", "OPERATING-SYSTEM", "FRAMEWORK", "INSTALL", "DEVICE", "FIRMWARE"}

# Trivy vulnerability Status -> applicability (https://trivy.dev: vulnerability status)
STATUS_APPLICABILITY = {
    "not_affected": "Không áp dụng", "fixed": "Áp dụng", "affected": "Áp dụng", "will_not_fix": "Áp dụng",
    "fix_deferred": "Áp dụng", "end_of_life": "Có thể", "under_investigation": "Chưa rõ", "unknown": "Áp dụng",
}
NO_FIX_STATUSES = {"affected", "will_not_fix", "fix_deferred", "end_of_life"}

# SPDX 2.3 dependency relationships: (chiều, scope). forward: element=cha, related=con
DEP_REL = {
    "DEPENDS_ON": ("fwd", None), "DEPENDENCY_OF": ("rev", None), "RUNTIME_DEPENDENCY_OF": ("rev", "runtime"),
    "DEV_DEPENDENCY_OF": ("rev", "dev"), "BUILD_DEPENDENCY_OF": ("rev", "build"), "TEST_DEPENDENCY_OF": ("rev", "test"),
    "OPTIONAL_DEPENDENCY_OF": ("rev", "optional"), "PROVIDED_DEPENDENCY_OF": ("rev", "provided"),
    "DEV_TOOL_OF": ("rev", "dev"), "BUILD_TOOL_OF": ("rev", "build"), "TEST_TOOL_OF": ("rev", "test"), "TEST_OF": ("rev", "test"),
}
SCOPE_RANK = {"runtime": 6, "provided": 5, None: 4, "optional": 3, "build": 2, "test": 1, "dev": 0}
NONPROD = {"dev", "test", "build"}

OSV_ECO = {"npm": "npm", "golang": "Go", "pypi": "PyPI", "maven": "Maven", "nuget": "NuGet", "cargo": "crates.io",
           "gem": "RubyGems", "composer": "Packagist", "pub": "Pub", "hex": "Hex", "swift": "SwiftURL"}
# Sản phẩm trên endoflife.date: (ecosystem, tên package) -> slug
EOL_PRODUCTS = {
    ("npm", "vue"): "vue", ("npm", "nuxt"): "nuxt", ("npm", "@angular/core"): "angular", ("npm", "react"): "react",
    ("npm", "next"): "nextjs", ("npm", "electron"): "electron", ("npm", "jquery"): "jquery",
    ("pypi", "django"): "django", ("maven", "org.springframework.boot:spring-boot"): "spring-boot",
    ("maven", "org.springframework:spring-core"): "spring-framework", ("composer", "laravel/framework"): "laravel",
    ("gem", "rails"): "rails", ("golang", "stdlib"): "go",
}
RUNTIME_PRODUCTS = [(re.compile(r"^(node|nodejs)$", re.I), "nodejs"), (re.compile(r"^stdlib$"), "go"),
                    (re.compile(r"^python3?(\.\d+)?$", re.I), "python"), (re.compile(r"^php\d*(\.\d+)?$", re.I), "php"),
                    (re.compile(r"^ruby\d*(\.\d+)?$", re.I), "ruby"), (re.compile(r"^(dotnet|aspnetcore)[\w.-]*$", re.I), "dotnet")]
OS_PRODUCTS = {"debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine", "rocky": "rocky-linux", "almalinux": "almalinux",
               "amazon": "amazon-linux", "rhel": "rhel", "redhat": "rhel", "centos": "centos", "opensuse": "opensuse"}

# Vị trí cài đặt trong image: quyết định phương án xử lý (app lockfile vs base image)
LOC_TOOLING_RE = re.compile(
    r"^(usr/(local/)?lib/node_modules/(npm|corepack|yarn|pnpm)(/|$)|opt/yarn[^/]*/|usr/(local/)?share/(yarn|npm|corepack)/|"
    r"root/\.(npm|cache|yarn)/|usr/(local/)?lib/python3[\d.]*/(site|dist)-packages/(pip|setuptools|wheel|pkg_resources|_distutils_hack)\b|"
    r"usr/lib/python3/dist-packages/(pip|setuptools|wheel)\b|usr/local/go/(pkg/mod|src/cmd|pkg/tool)/)")
LOC_GLOBAL_RE = re.compile(r"^(usr/(local/)?lib/node_modules/|usr/(local/)?lib/python3[\d.]*/(site|dist)-packages/|"
                           r"usr/lib/python3/dist-packages/|usr/share/java/|usr/local/lib/ruby/|usr/lib/jvm/)")
LOC_BINARY_RE = re.compile(r"^(usr/(local/)?s?bin/|s?bin/|usr/libexec/)")
IMAGE_LOCS = {"base-image tooling", "image (global)", "image binary"}
LOC_LABEL = {"app": "app", "base-image tooling": "base-image tooling", "image (global)": "image (global)", "image binary": "image binary"}


def classify_location(path):
    """Đường dẫn trong image -> app | base-image tooling | image (global) | image binary | None (không rõ)."""
    if not path or "/" not in path:
        return None  # vd target "Node.js", "Python" của Trivy: không có đường dẫn
    p = path.strip().lstrip("/")
    if OS_TARGET_RE.search(p):
        return None
    if LOC_TOOLING_RE.match(p):
        return "base-image tooling"
    if LOC_GLOBAL_RE.match(p):
        return "image (global)"
    if LOC_BINARY_RE.match(p):
        return "image binary"
    return "app"


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
OSV_URL = "https://api.osv.dev/v1/query"
EOL_URL = "https://endoflife.date/api/{}.json"


# ================================================================= helpers
def canon_id(vid):
    """CVE-/DSA-... viết hoa; GHSA giữ dạng chuẩn GHSA-xxxx-xxxx-xxxx (chữ thường)."""
    vid = (vid or "").strip()
    if vid.upper().startswith("GHSA-"):
        return "GHSA-" + vid[5:].lower()
    return vid.upper()


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


MAX_RESPONSE = 50 * 1024 * 1024  # 50MB - KEV ~1-2MB, OSV/EPSS/endoflife nhỏ hơn nhiều
MAX_CONTENT = 20000                # ký tự đọc từ trường content của mỗi issue Trivy


def http_json(url, data=None, timeout=20):
    """Chỉ gọi HTTPS tới các URL cố định ở trên; không gửi token/thông tin người dùng; giới hạn kích thước phản hồi."""
    if not url.startswith("https://"):
        raise ValueError("chỉ cho phép https")
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json", "User-Agent": "dependency-risk-analysis"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read(MAX_RESPONSE + 1)
    if len(body) > MAX_RESPONSE:
        raise ValueError("phản hồi quá lớn")
    return json.loads(body)


def norm_name(name, eco=None):
    n = (name or "").strip()
    if eco not in ("golang", "maven"):
        n = n.lower()
    if eco == "pypi":
        n = re.sub(r"[-_.]+", "-", n)
    return n


def parse_purl(purl):
    if not purl or not str(purl).startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0]
    quals = {}
    if "?" in body:
        body, q = body.split("?", 1)
        for kv in q.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                quals[k.lower()] = unquote(v)
    version = None
    if "@" in body:
        body, version = body.rsplit("@", 1)
        version = unquote(version)
    parts = [unquote(p) for p in body.split("/") if p]
    ptype = parts[0].lower()
    ns, name = parts[1:-1], parts[-1]
    if ptype == "maven" and ns:
        display = f"{'.'.join(ns)}:{name}"
    elif ptype in OS_TYPES:
        display = name
    elif ns:
        display = "/".join(ns + [name])
    else:
        display = name
    return {"type": ptype, "display": display, "namespace": "/".join(ns), "version": version, "qualifiers": quals}


def purl_key(purl):
    """Định danh: type/namespace/name@version + distro (gói OS). Không gộp gói cùng tên ở distro khác nhau."""
    p = parse_purl(purl)
    if not p:
        return None
    key = f"{p['type']}/{norm_name(p['display'], p['type'])}@{p['version']}"
    if p["type"] in OS_TYPES and p["qualifiers"].get("distro"):
        key += f"?distro={p['qualifiers']['distro'].lower()}"
    return key


def name_key(name, version):
    return (norm_name(name), version)


def split_fixed(s):
    return [f.strip() for f in re.split(r"[,\s]+", s or "") if f.strip() and re.search(r"\d", f)]


def parse_time(s):
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(str(s).replace("Z", "+00:00")[:32])
    except ValueError:
        m = re.match(r"(\d{4}-\d{2}-\d{2})", str(s))
        return dt.datetime.fromisoformat(m.group(1) + "T00:00:00+00:00") if m else None


def image_ref(name):
    """registry/ns/img:tag (os) -> ns/img:tag (bỏ registry & phần OS) để so khớp artifact."""
    if not name:
        return None
    n = OS_TARGET_RE.sub("", name).strip().split("@")[0]
    parts = n.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        parts = parts[1:]
    return "/".join(parts).lower() or None


# ================================================================= Trivy
def _field(text, *labels):
    """Đọc 'Label: value' từ content (dữ liệu không tin cậy): lượng từ có giới hạn để tránh ReDoS."""
    for lb in labels:
        m = re.search(rf"(?im)^[^\w\n]{{0,8}}{lb}[^\w\n:|]{{0,4}}[:|][ \t]{{0,4}}\*{{0,2}}`?([^\n|`*]{{1,200}})", text or "")
        if m:
            return m.group(1).strip().strip("*` ")
    return None


def parse_trivy(data, ctx):
    vulns, others, info = ctx["vulns"], ctx["others"], ctx["trivy_info"]
    if isinstance(data, dict) and "Results" in data:
        info["formats"].add("native")
        ctx.setdefault("file_format", {})[ctx.get("cur_file")] = "Trivy JSON gốc"
        md = data.get("Metadata") or {}
        info["artifacts"].append({"name": data.get("ArtifactName"), "digests": md.get("RepoDigests") or [],
                                  "image_id": md.get("ImageID"), "created": data.get("CreatedAt")})
        osm = md.get("OS") or {}
        if osm.get("Family"):
            info["os"] = {"family": osm.get("Family"), "name": osm.get("Name"), "eosl": bool(osm.get("EOSL"))}
        for res in data.get("Results") or []:
            tgt, cls = res.get("Target", ""), res.get("Class", "")
            for p in res.get("Packages") or []:
                purl = (p.get("Identifier") or {}).get("PURL")
                k = purl_key(purl) if purl else None
                rel = (p.get("Relationship") or "").lower()
                if rel in ("root", "workspace") and p.get("Name"):
                    ctx["trivy_roots"].add(p["Name"].lower())
                    continue
                if k:
                    ctx["trivy_pkgs"][k] = {"dev": bool(p.get("Dev")), "path": p.get("FilePath"),
                                            "relation": "direct" if rel == "direct" else "transitive" if rel == "indirect" or p.get("Indirect") else None}
            for v in res.get("Vulnerabilities") or []:
                vulns.append({
                    "id": canon_id(v.get("VulnerabilityID")), "severity": (v.get("Severity") or "UNKNOWN").upper(),
                    "pkg": v.get("PkgName"), "installed": v.get("InstalledVersion"),
                    "purl": (v.get("PkgIdentifier") or {}).get("PURL"),
                    "fixed": split_fixed(v.get("FixedVersion")), "fixed_source": "Trivy" if v.get("FixedVersion") else None,
                    "status": (v.get("Status") or "").lower() or None, "title": (v.get("Title") or "")[:120],
                    "target": tgt, "is_os": cls == "os-pkgs", "aliases": [], "src": ctx.get("cur_file"),
                    "pkg_path": v.get("PkgPath") or (tgt if cls == "lang-pkgs" else None)})
            for m in res.get("Misconfigurations") or []:
                if (m.get("Status") or "").upper() != "PASS":
                    others.append({"check": "misconfig", "severity": m.get("Severity"), "title": (m.get("Title") or "")[:120], "path": tgt,
                                   "src": ctx.get("cur_file")})
            for s in res.get("Secrets") or []:
                others.append({"check": "secret", "severity": s.get("Severity"), "title": (s.get("Title") or "")[:120], "path": tgt,
                               "src": ctx.get("cur_file")})
        return
    info["formats"].add("codequality")
    ctx.setdefault("file_format", {})[ctx.get("cur_file")] = "Trivy code-quality"
    for it in data or []:
        desc = it.get("description") or ""
        content = it.get("content") or ""
        if isinstance(content, dict):
            content = content.get("body", "")
        content = str(content)[:MAX_CONTENT]
        desc = str(desc)[:2000]
        sev_raw = it.get("severity") or "UNKNOWN"
        sev = CQ_TO_SEV.get(sev_raw.lower(), sev_raw.upper())
        path = (it.get("location") or {}).get("path", "")
        m = VULN_ID_RE.search(desc) or VULN_ID_RE.search(content)
        if not m:
            others.append({"check": it.get("check_name"), "severity": sev, "title": desc[:160], "path": path, "src": ctx.get("cur_file"),
                           "advisory_without_id": it.get("check_name") in ("container_scanning", "dependency_scanning")})
            continue
        if OS_TARGET_RE.search(path):
            info["artifacts"].append({"name": OS_TARGET_RE.sub("", path).strip(), "digests": [], "created": None})
        parts = [p.strip() for p in desc.split(" - ")]
        # Template gitlab-codequality của Trivy: "<ID> - <PkgName> - <InstalledVersion> - <Title>"; content = mô tả CVE
        pkg = _field(content, r"Package(?:\s*Name)?", "PkgName", "Library") or (parts[1] if len(parts) >= 3 else None)
        inst = _field(content, r"Installed\s*Version", "InstalledVersion") or (parts[2] if len(parts) >= 3 else None)
        fixed = _field(content, r"Fixed\s*Version", "FixedVersion", r"Fixed\s*in")
        status = _field(content, "Status")
        title = _field(content, "Title") or (" - ".join(parts[3:]) if len(parts) > 3 else desc)
        vulns.append({"id": canon_id(m.group(1)), "severity": sev, "pkg": pkg, "installed": inst, "purl": None,
                      "fixed": split_fixed(fixed), "fixed_source": "Trivy" if fixed else None,
                      "status": status.lower().replace(" ", "_") if status else None, "title": (title or "")[:120],
                      "target": path, "is_os": bool(OS_TARGET_RE.search(path)), "aliases": [], "src": ctx.get("cur_file"),
                      "pkg_path": None if OS_TARGET_RE.search(path) else path})


# ================================================================= SBOM
def parse_sbom(doc, root_names=()):
    nodes, by_purl, by_name = {}, defaultdict(list), defaultdict(list)
    for p in doc.get("packages", []):
        purl = next((r.get("referenceLocator") for r in p.get("externalRefs", []) if r.get("referenceType") == "purl"), None)
        pp = parse_purl(purl) or {}
        ann = {}
        for a in p.get("annotations", []):
            c = a.get("comment", "")
            if ": " in c:
                k, v = c.split(": ", 1)
                ann.setdefault(k.strip(), v.strip())
        sid = p.get("SPDXID")
        nodes[sid] = {"spdxid": sid, "name": pp.get("display") or p.get("name"), "raw_name": p.get("name"), "version": pp.get("version") or p.get("versionInfo"),
                      "purl": purl, "eco": pp.get("type"), "qualifiers": pp.get("qualifiers", {}),
                      "purpose": p.get("primaryPackagePurpose"), "license": p.get("licenseDeclared") or p.get("licenseConcluded"),
                      "source": p.get("sourceInfo"), "ann": ann,
                      "dev_mark": str(ann.get("Dev", ann.get("PkgDev", ""))).lower() == "true",
                      "path": ann.get("PkgPath") or ann.get("FilePath")}
        if purl:
            by_purl[purl_key(purl)].append(sid)
        if nodes[sid]["name"]:
            by_name[name_key(nodes[sid]["name"], nodes[sid]["version"])].append(sid)
    dep_parents, dep_children = defaultdict(list), defaultdict(list)  # node -> [(other, scope)]
    contains, contained_by = defaultdict(list), defaultdict(set)
    for r in doc.get("relationships", []):
        a, b, t = r.get("spdxElementId"), r.get("relatedSpdxElement"), r.get("relationshipType")
        if t in DEP_REL:
            direction, scope = DEP_REL[t]
            parent, child = (a, b) if direction == "fwd" else (b, a)
            dep_parents[child].append((parent, scope))
            dep_children[parent].append((child, scope))
        elif t == "CONTAINS":
            contains[a].append(b)
            contained_by[b].add(a)
        elif t == "CONTAINED_BY":
            contains[b].append(a)
            contained_by[a].add(b)
    project_root_ids = {s for s, n in nodes.items() if (n["name"] or "").lower() in root_names
                        and n["purpose"] not in ("CONTAINER", "OPERATING-SYSTEM")}
    roots = {s for s, n in nodes.items() if n["purpose"] in ROOT_PURPOSES or s.startswith("SPDXRef-Application")} | project_root_ids
    in_graph = set(dep_parents) | set(dep_children)
    app_has_graph = {r: (r in in_graph) or any(c in in_graph for c in contains.get(r, [])) for r in roots}
    g = {"nodes": nodes, "by_purl": by_purl, "by_name": by_name, "dep_parents": dep_parents, "dep_children": dep_children,
         "contains": contains, "contained_by": contained_by, "roots": roots, "app_has_graph": app_has_graph,
         "files": {f.get("SPDXID"): f.get("fileName") for f in doc.get("files", [])}, "doc": doc,
         "project_root_ids": project_root_ids}
    g["scope"] = compute_scopes(g)
    return g


def _child_label(parent_label, edge_scope):
    if edge_scope in NONPROD:
        return edge_scope
    if parent_label in NONPROD:
        return parent_label
    if edge_scope == "optional":
        return "optional"
    return parent_label


def compute_scopes(g):
    """Scope của từng node: runtime / dev / test / build / optional / provided / None (không rõ).
    Lan truyền từ root ứng dụng (runtime) và từ các đỉnh của dependency graph (không rõ trừ khi có dấu Dev)."""
    labels, q = {}, deque()
    for r in g["roots"]:
        labels[r] = "runtime"
        q.append(r)
    for s, n in g["nodes"].items():
        if s not in g["roots"] and not g["dep_parents"].get(s) and (s in g["dep_children"] or n["dev_mark"]):
            labels[s] = "dev" if n["dev_mark"] else None
            q.append(s)
    while q:
        n = q.popleft()
        for c, sc in g["dep_children"].get(n, ()):
            new = "dev" if g["nodes"].get(c, {}).get("dev_mark") else _child_label(labels[n], sc)
            if c not in labels or SCOPE_RANK[new] > SCOPE_RANK[labels[c]]:
                labels[c] = new
                q.append(c)
    return labels


def sid_location(g, sid):
    n = g["nodes"][sid]
    loc = classify_location(n.get("path"))
    if loc:
        return loc
    for a in g["contained_by"].get(sid, ()):  # Application của Trivy thường mang tên lockfile, vd app/package-lock.json
        if a in g["roots"] and g["nodes"][a]["purpose"] == "APPLICATION":
            loc = classify_location(g["nodes"][a].get("raw_name"))
            if loc:
                return loc
    return None


def _label(g, s):
    n = g["nodes"].get(s)
    if not n:
        return s
    return f"{n['name']}@{n['version']}" if n.get("version") else n["name"]


def dep_info(sids, g, max_paths=3):
    """Gộp thông tin phụ thuộc cho mọi vị trí (SPDXID) của cùng một package."""
    roots = g["roots"]
    dependents, paths, rels, scopes, locations, files, direct_parents = set(), [], [], [], [], [], set()
    for sid in sids:
        seen, q = {sid}, deque([sid])
        while q:
            for p, _ in g["dep_parents"].get(q.popleft(), ()):
                if p not in seen:
                    seen.add(p)
                    q.append(p)
        dependents |= {s for s in seen if s != sid and s not in roots}
        # đường đi ngắn nhất tới đỉnh graph
        q, best = deque([[sid]]), {}
        while q and len(paths) < max_paths:
            path = q.popleft()
            ps = g["dep_parents"].get(path[-1])
            if not ps:
                chain = list(reversed(path))
                if chain[0] not in roots:
                    r = next((c for c in g["contained_by"].get(chain[0], ()) if c in roots), None)
                    if r:
                        chain = [r] + chain
                if len(chain) > 1:
                    s = " → ".join(_label(g, x) for x in chain)
                    if s not in paths:
                        paths.append(s)
                continue
            for p, _ in sorted(ps, key=lambda x: x[0]):
                if p in path or best.get(p, 99) < len(path):
                    continue
                best[p] = len(path)
                q.append(path + [p])
        ps = [p for p, _ in g["dep_parents"].get(sid, ())]
        direct_parents |= {_label(g, p) for p in ps if p not in roots}
        apps = [c for c in g["contained_by"].get(sid, ()) if c in roots]
        locations += [g["nodes"][a]["raw_name"] for a in apps if g["nodes"][a].get("raw_name") and g["nodes"][a]["purpose"] == "APPLICATION"]
        if any(p in roots for p in ps):
            rels.append(("direct", "sbom"))
        elif ps:
            rels.append(("transitive", "sbom"))
        elif any(g["app_has_graph"].get(a) for a in apps):
            rels.append(("direct", "sbom-inferred"))  # đỉnh graph của một ứng dụng có dữ liệu graph
        scopes.append(g["scope"].get(sid, None) if sid in g["scope"] else None)
        fp = g["nodes"][sid]["ann"].get("FilePath")
        if fp:
            files.append(fp)
        files += [g["files"][f] for f in g["contains"].get(sid, []) if f in g["files"]]
    order = {("direct", "sbom"): 3, ("direct", "sbom-inferred"): 2, ("transitive", "sbom"): 1}
    rel = max(rels, key=lambda x: order[x]) if rels else (None, None)
    scope = max(scopes, key=lambda s: SCOPE_RANK[s]) if scopes else None
    via = set()
    for p in paths:
        names = [x.rsplit("@", 1)[0] for x in p.split(" → ")]
        top_is_root = any(g["nodes"][r]["name"] == names[0] for r in roots if g["nodes"][r].get("name"))
        if len(names) > 2:
            via.add(names[1] if top_is_root else names[0])
        elif len(names) == 2 and not top_is_root:
            via.add(names[0])
    return {"relation_sbom": rel[0], "relation_basis": rel[1], "scope": scope, "paths": paths,
            "via_direct": sorted(via) if rel[0] == "transitive" else [], "dependents_total": len(dependents),
            "direct_parents": sorted(direct_parents)[:5], "locations": sorted(set(locations)), "occurrences": len(sids),
            "files": list(dict.fromkeys(files))[:3]}


# ================================================================= external context
def load_kev(path=None, online=False, status=None):
    data = None
    try:
        if path:
            data = load(path)
        elif online:
            data = http_json(KEV_URL)
    except Exception as e:
        status["kev"] = f"lỗi: {str(e)[:80]}"
        return None
    if not data:
        return None
    kev = {canon_id(v.get("cveID")): {"date_added": v.get("dateAdded"), "ransomware": v.get("knownRansomwareCampaignUse")}
           for v in data.get("vulnerabilities", [])}
    status["kev"] = f"{len(kev)} CVE ({'file' if path else 'online'})"
    return kev


def load_epss(path=None, cves=(), online=False, status=None):
    epss = {}
    try:
        if path:
            raw = gzip.open(path, "rt", encoding="utf-8") if path.endswith(".gz") else open(path, encoding="utf-8")
            with raw as fh:
                rows = csv.DictReader(io.StringIO("".join(l for l in fh if not l.startswith("#"))))
                for r in rows:
                    epss[canon_id(r["cve"])] = (float(r["epss"]), float(r.get("percentile") or 0))
            status["epss"] = f"{len(epss)} CVE (file)"
        elif online and cves:
            cl = sorted(c for c in cves if c.startswith("CVE-"))
            for i in range(0, len(cl), 80):
                d = http_json(EPSS_URL + ",".join(cl[i:i + 80]))
                for r in d.get("data", []):
                    epss[canon_id(r["cve"])] = (float(r["epss"]), float(r.get("percentile") or 0))
            status["epss"] = f"{len(epss)}/{len(cl)} CVE (online)"
    except Exception as e:
        status["epss"] = f"lỗi: {str(e)[:80]}"
        return None
    return epss if (path or (online and cves)) else None


def osv_ecosystem(eco, quals):
    if eco in OSV_ECO:
        return OSV_ECO[eco]
    distro = (quals or {}).get("distro", "")
    m = re.match(r"debian-(\d+)", distro)
    if eco == "deb" and m:
        return f"Debian:{m.group(1)}"
    m = re.match(r"alpine-(\d+\.\d+)", distro)
    if eco == "apk" and m:
        return f"Alpine:v{m.group(1)}"
    return None


def osv_query(name, version, ecosystem):
    return http_json(OSV_URL, {"package": {"name": name, "ecosystem": ecosystem}, "version": version}).get("vulns", [])


def osv_match(vid, osv_vulns, pkg_name):
    """-> (fixed_list, ranges, aliases) hoặc None nếu OSV không có bản ghi cho CVE này."""
    for ov in osv_vulns:
        ids = {canon_id(x) for x in [ov.get("id", "")] + ov.get("aliases", []) + ov.get("upstream", [])}
        if canon_id(vid) not in ids:
            continue
        fixed, ranges = [], []
        for aff in ov.get("affected", []):
            if norm_name((aff.get("package") or {}).get("name")) != norm_name(pkg_name):
                continue
            for rg in aff.get("ranges", []):
                ranges.append(rg)
                fixed += [e["fixed"] for e in rg.get("events", []) if e.get("fixed")]
        return sorted(set(fixed)), ranges, sorted(ids - {canon_id(vid)})
    return None


def is_private(f, patterns):
    """Package nội bộ: khớp --private-pattern, hoặc Uzomuzo không tìm thấy trong registry công khai."""
    name = f.get("name") or ""
    if any(fnmatch.fnmatchcase(name, p) for p in patterns):
        return True
    err = ((f.get("uzomuzo") or {}).get("error") or "").lower()
    return "not found" in err or "404" in err


def enrich_osv(findings, query=osv_query, private_patterns=()):
    st = {"queried": 0, "matched": 0, "filled": 0, "errors": 0, "skipped_private": 0}
    cache = {}
    for f in findings.values():
        if not f["vulns"]:
            continue
        eco = osv_ecosystem(f["ecosystem"], f.get("qualifiers"))
        is_os = f["ecosystem"] in OS_TYPES
        qname = f.get("os_source_name") if is_os else f["name"]
        qver = (f.get("os_source_version") or f["version"]) if is_os else f["version"]
        if not eco or not qname:
            continue
        if f["kind"] == "app" and is_private(f, private_patterns):
            st["skipped_private"] += 1
            continue
        ck = (qname, qver, eco)
        try:
            if ck not in cache:
                cache[ck] = query(qname, qver, eco)
                st["queried"] += 1
        except Exception as e:
            st["errors"] += 1
            st["last_error"] = str(e)[:100]
            if st["errors"] >= 3 and st["queried"] == 0:
                st["aborted"] = True
                break
            continue
        for v in f["vulns"]:
            m = osv_match(v["id"], cache[ck], qname)
            if m is None:
                continue
            fixed, ranges, aliases = m
            st["matched"] += 1
            v["aliases"] = sorted(set(v["aliases"]) | set(aliases))
            v["alias_checked"] = True
            if ranges and not is_os:
                v["osv_ranges"] = ranges
            if fixed and not v["fixed"]:
                v["fixed"], v["fixed_source"] = fixed, "OSV"
                st["filled"] += 1
            elif not fixed and not v["fixed"]:
                v["osv_no_fix"] = True
    return st


def eol_lookup(product, version, cache, status, today):
    if product not in cache:
        try:
            cache[product] = http_json(EOL_URL.format(product))
        except Exception as e:
            cache[product] = None
            status["errors"] = status.get("errors", 0) + 1
            status["last_error"] = str(e)[:80]
    cycles = cache.get(product)
    if not cycles or not version:
        return None
    v = re.sub(r"^[vV]", "", str(version))
    best = None
    for c in cycles:
        cy = str(c.get("cycle"))
        if v == cy or v.startswith(cy + ".") or v.startswith(cy + "-"):
            if not best or len(cy) > len(str(best.get("cycle"))):
                best = c
    if not best:
        return None
    eol = best.get("eol")
    is_eol = eol is True or (isinstance(eol, str) and eol <= today)
    supported = [c for c in cycles if not (c.get("eol") is True or (isinstance(c.get("eol"), str) and c["eol"] <= today))]
    return {"product": product, "cycle": str(best.get("cycle")), "eol": eol, "is_eol": bool(is_eol),
            "latest_in_cycle": best.get("latest"), "newest_supported_cycle": str(supported[0]["cycle"]) if supported else None,
            "source": "endoflife.date"}


# ================================================================= đánh giá
def classify_lifecycle(f):
    """-> (eol_status, basis[]). Phân biệt: dự án ngừng bảo trì / nhánh version hết hỗ trợ / bảo trì hạn chế."""
    u = f.get("uzomuzo") or {}
    life = (u.get("lifecycle") or "").lower()
    basis = []
    if u.get("archived"):
        basis.append("repo archived")
    if u.get("disabled"):
        basis.append("repo disabled")
    if u.get("verdict") == "replace":
        basis.append("Uzomuzo: replace")
    if any(k in life for k in ("eol", "end-of-life", "end of life", "deprecated", "abandon")):
        basis.append(f"lifecycle {u['lifecycle']}")
    if basis:
        return "Ngừng bảo trì", basis
    ei = f.get("eol_info")
    if ei and ei.get("is_eol"):
        return "Nhánh hết hỗ trợ", [f"{ei['product']} {ei['cycle']} EOL {ei['eol'] if ei['eol'] is not True else ''} ({ei['source']})".replace("  ", " ")]
    if u.get("verdict") == "caution" or "stalled" in life:
        return "Bảo trì hạn chế", [f"Uzomuzo: {u.get('verdict')}/{u.get('lifecycle')}"]
    return None, []


def choose_target(f, active):
    eco, inst = f["ecosystem"], f["version"]
    with_fix = [v for v in active if v["fixed"] or v.get("osv_ranges")]
    cands = [c for c in V.sort_versions([x for v in with_fix for x in v["fixed"]], eco)
             if not inst or V.compare(c, inst, eco) > 0]

    def covered(t):
        return [v["id"] for v in with_fix if V.fixes(t, inst, v["fixed"], eco, v.get("osv_ranges"))]

    def best_of(cs):
        best, best_n = None, -1
        for c in cs:
            n = len(covered(c))
            if n > best_n:
                best, best_n = c, n
            if n == len(with_fix):
                break
        return best

    target = best_of(cands)
    res = {"target_version": target, "fixed_ids": covered(target) if target else []}
    if target and inst and V.branch(target, eco, 1) != V.branch(inst, eco, 1) and eco not in OS_TYPES:
        same = [c for c in cands if V.branch(c, eco, 1) == V.branch(inst, eco, 1)]
        alt = best_of(same)
        if alt and covered(alt):
            res["same_major_target"] = alt
            res["same_major_leaves_unfixed"] = [v["id"] for v in active if v["id"] not in covered(alt)]
    return res


def upgrade_type(cur, target, eco):
    if not cur or not target:
        return None
    if eco in OS_TYPES:
        return "os-patch"
    (cM, cm), (tM, tm) = V.branch(cur, eco), V.branch(target, eco)
    if tM != cM:
        return "major"
    if cM == 0 and tm != cm:
        return "minor-0x"
    return "minor" if tm != cm else "patch"


def evaluate(f, ctx):
    u = f.get("uzomuzo") or {}
    kev, epss = ctx["kev"], ctx["epss"]
    for v in f["vulns"]:
        v["applicability"] = STATUS_APPLICABILITY.get(v.get("status") or "unknown", "Áp dụng")
        if v["fixed"]:
            v["fix_state"] = "có"
        elif (v.get("status") in NO_FIX_STATUSES) or v.get("osv_no_fix"):
            v["fix_state"] = "không có"
        else:
            v["fix_state"] = "chưa rõ"
        ids = [v["id"]] + v.get("aliases", [])
        v["kev"] = bool(kev) and any(i in kev for i in ids)
        e = [epss[i] for i in ids if epss and i in epss]
        v["epss"] = max(e)[0] if e else None
    f["vulns"].sort(key=lambda x: (-SEV_ORDER.get(x["severity"], 0), x["id"]))
    active = [v for v in f["vulns"] if v["applicability"] != "Không áp dụng"]
    f["suppressed"] = [v["id"] for v in f["vulns"] if v["applicability"] == "Không áp dụng"]
    f["active_vulns"] = len(active)
    f["max_severity"] = max((v["severity"] for v in active), key=lambda s: SEV_ORDER.get(s, 0)) if active else None

    # --- phương án version
    t = choose_target(f, active)
    f.update(t)
    f["target_source"] = sorted({v["fixed_source"] for v in active if v["fixed"] and v["fixed_source"]}) or None
    f["latest_stable"] = u.get("stable_version")  # bản ổn định mới nhất, KHÔNG phải bản vá
    f["upgrade_type"] = upgrade_type(f["version"], f["target_version"], f["ecosystem"])
    f["unfixed_ids"] = [v["id"] for v in active if v["id"] not in f["fixed_ids"]]
    if not active:
        f["fix_coverage"] = None
    elif f["target_version"] and not f["unfixed_ids"]:
        f["fix_coverage"] = "full"
    elif f["target_version"]:
        f["fix_coverage"] = "partial"
    elif all(v["fix_state"] == "không có" for v in active):
        f["fix_coverage"] = "none"
    else:
        f["fix_coverage"] = "unknown"
    f["fix_summary"] = f"vá {len(f['fixed_ids'])}/{len(active)} CVE" if active else None

    # --- vòng đời
    f["eol_status"], f["eol_basis"] = classify_lifecycle(f)

    # --- ưu tiên: severity là điểm gốc; KEV/EPSS/scope/vòng đời điều chỉnh
    basis = []
    if active:
        score = SEV_BASE.get(f["max_severity"], 0)
        basis.append(f"severity {f['max_severity']}")
        if any(v["kev"] for v in active):
            basis.append("CISA KEV")
        top_epss = max((v["epss"] for v in active if v["epss"] is not None), default=None)
        if top_epss is not None:
            basis.append(f"EPSS {top_epss:.2f}")
            if top_epss >= 0.1:
                score += 1
        if f["eol_status"] == "Ngừng bảo trì" and f["fix_coverage"] in ("none", "unknown"):
            score += 1
            basis.append("ngừng bảo trì, không có bản vá")
    else:
        score = -1
    life_score = {"Ngừng bảo trì": 2, "Nhánh hết hỗ trợ": 2, "Bảo trì hạn chế": 1}.get(f["eol_status"], -1)
    if life_score >= 0 and not active:
        basis.append(f"vòng đời: {f['eol_status']}")
    score = max(score, life_score)
    scope = f.get("scope")
    if scope in NONPROD and score > 0:
        score -= 1
        basis.append(f"chỉ dùng cho {scope}")
    if score < 0 and (u.get("verdict") == "review" or u.get("error")):
        score = 0
        basis.append("Uzomuzo chưa đánh giá được")
    elif score < 0 and u.get("build_integrity") == "Weak":
        score = 0
        basis.append("build integrity Weak")
    if active and any(v["kev"] for v in active):
        score = max(score, 3)
    f["suggested_priority"] = {3: "P1", 2: "P2", 1: "P3", 0: "P4"}.get(min(score, 3)) if score >= 0 else None
    f["priority_basis"] = basis
    f["exploit_context"] = "đã kiểm tra" if (kev is not None or epss is not None) else "chưa kiểm tra"

    # --- những gì cần xác minh (blocking = chưa đủ căn cứ để quyết định)
    blocking, notes = [], []
    if active and all(v["applicability"] in ("Chưa rõ",) for v in active):
        blocking.append("Vendor đang điều tra (under_investigation) → chờ/tra advisory xác định có bị ảnh hưởng không")
    if not active and not f["eol_status"] and (u.get("verdict") == "review" or u.get("error")):
        blocking.append(f"Uzomuzo không đánh giá được ({u.get('error') or u.get('lifecycle') or 'review'}) → kiểm tra nguồn gốc/registry")
    elif active and (u.get("verdict") == "review" or u.get("error")):
        notes.append("Vòng đời chưa đánh giá được (Uzomuzo review) - không ảnh hưởng quyết định xử lý CVE")
    if any(v["applicability"] == "Có thể" for v in active):
        notes.append("Trivy status end_of_life: gói/distro hết hỗ trợ nên không có bản vá → nâng base image/nhánh còn hỗ trợ")
    if f.get("join") == "not_in_sbom" and active:
        notes.append("Trivy báo nhưng không có trong SBOM → kiểm tra Trivy và SBOM có cùng artifact/lần quét")
    elif f.get("join") == "not_in_sbom" and f.get("uzomuzo"):
        blocking.append("Uzomuzo đánh giá package không có trong SBOM của image (có thể chỉ có ở source/devDependency) → kiểm tra package có trong artifact không")
    if f.get("uzomuzo_version"):
        notes.append(f"Uzomuzo đánh giá version {f['uzomuzo_version']} (image có {f['version']}) - ghép theo tên; thông tin version (license) có thể khác")
    if f.get("join") == "ambiguous":
        notes.append("Trùng tên với nhiều package trong SBOM → chưa xác định được quan hệ phụ thuộc")
    if f.get("relation_conflict"):
        notes.append(f["relation_conflict"])
    unk = [v["id"] for v in active if v["fix_state"] == "chưa rõ"]
    if unk and f["kind"] == "app":
        notes.append(f"Chưa có thông tin bản vá cho {', '.join(unk[:3])}{' +' + str(len(unk) - 3) if len(unk) > 3 else ''} → tra OSV/GHSA/advisory")
    if f["fix_coverage"] == "partial":
        notes.append(f"Version đích chỉ {f['fix_summary']}; còn {', '.join(f['unfixed_ids'][:3])}")
    if f["kind"] == "os" and any(v["fix_state"] != "có" for v in active):
        notes.append("Gói OS chưa có bản vá → xem security tracker của distro; đánh giá mitigation hoặc đổi base image (không tự hạ ưu tiên)")
    f["verify"] = blocking + notes
    f["verify_blocking"] = bool(blocking)

    p = f["suggested_priority"]
    f["decision"] = "Cần xác minh" if blocking else "Cần xử lý" if p in ("P1", "P2", "P3") else "Theo dõi" if p == "P4" else None
    f["category"] = [c for c, ok in (("CVE", active), ("EOL", f["eol_status"])) if ok]
    f["section"] = ("EOL" if f["eol_status"] in ("Ngừng bảo trì", "Nhánh hết hỗ trợ") else "CVE" if active
                    else "EOL" if f["eol_status"] else "Xác minh" if blocking else "Khác")
    f["breaking_basis"] = "sơ bộ theo semver" if f["upgrade_type"] else None

    # --- vị trí cài đặt → phương án đúng chỗ + người xử lý
    loc = f.get("install_location")
    via = (f.get("sbom") or {}).get("via_direct") or []
    if f["kind"] == "os":
        f["remediation_hint"] = "Rebuild / nâng base image để nhận bản vá của distro"
    elif loc == "base-image tooling":
        tool = (f.get("install_path") or "").split("node_modules/")[1].split("/")[0] if "node_modules/" in (f.get("install_path") or "") else "công cụ"
        f["remediation_hint"] = (f"Nằm trong {tool} của base image, không phải dependency của app: nâng base image hoặc cập nhật {tool} "
                                 f"trong Dockerfile, hoặc loại {tool} khỏi runtime image (multi-stage/distroless). "
                                 f"overrides/resolutions trong package.json của app KHÔNG tác động tới bản này")
    elif loc == "image (global)":
        f["remediation_hint"] = "Cài toàn cục trong image (không qua lockfile của app): cập nhật ở Dockerfile/base image nơi cài package này"
    elif loc == "image binary":
        f["remediation_hint"] = "Nằm trong binary của image: cập nhật/rebuild binary hoặc base image chứa nó"
    elif f.get("relation") == "transitive":
        f["remediation_hint"] = f"Nâng thư viện cha ({', '.join(via[:3]) or '?'}); overrides/resolutions chỉ là tạm thời"
    elif f.get("relation") == "direct":
        f["remediation_hint"] = "Nâng direct dependency trong manifest/lockfile của app"
    else:
        f["remediation_hint"] = "Xác định direct/transitive (npm ls / go mod why / pipdeptree) rồi nâng trong lockfile của app"
    f["scope_display"] = loc if loc in IMAGE_LOCS else (f.get("scope") or "không rõ") if f["kind"] == "app" else "base image (OS)"
    f["owner_hint"] = "Platform" if (f["kind"] == "os" or loc in IMAGE_LOCS) else "Web/App"
    if loc in IMAGE_LOCS:
        basis.append(f"vị trí: {loc}")


# ================================================================= main
def main(argv=None, osv_query_fn=None, http_fn=None):
    """http_fn / osv_query_fn: thay thế truy cập mạng (dùng khi kiểm thử)."""
    global http_json
    original = http_json
    if http_fn:
        http_json = http_fn
    try:
        return _main(argv, osv_query_fn)
    finally:
        http_json = original


def _main(argv, osv_query_fn):
    ap = argparse.ArgumentParser()
    ap.add_argument("--trivy", action="append", default=[])
    ap.add_argument("--uzomuzo")
    ap.add_argument("--sbom")
    ap.add_argument("--kev")
    ap.add_argument("--epss")
    ap.add_argument("--osv", action="store_true")
    ap.add_argument("--online", action="store_true")
    ap.add_argument("--private-pattern", action="append", default=[],
                    help="glob tên package nội bộ không được gửi ra ngoài, vd '@acme/*', 'com.acme.*', 'git.acme.com/*'")
    ap.add_argument("--project", action="append", default=[],
                    help="thư mục source của project: chỉ đọc package.json/go.mod/pyproject/pom để nhận diện project gốc")
    ap.add_argument("--root-package", action="append", default=[], help="tên package gốc (chính project), lặp được")
    ap.add_argument("--deployed-image", help="registry/image:tag đang chạy")
    ap.add_argument("--deployed-digest", help="sha256:... của image đang chạy")
    ap.add_argument("--environment", help="production / staging / test")
    ap.add_argument("--revision", help="commit SHA của source")
    ap.add_argument("--today", help="YYYY-MM-DD (mặc định: hôm nay) - dùng khi kiểm thử")
    ap.add_argument("-o", "--output", default="analysis.json")
    a = ap.parse_args(argv)
    if not (a.trivy or a.uzomuzo or a.sbom):
        sys.exit("Cần ít nhất một trong --trivy / --uzomuzo / --sbom")
    today = a.today or dt.date.today().isoformat()

    ctx = {"vulns": [], "others": [], "trivy_pkgs": {}, "trivy_roots": set(),
           "trivy_info": {"formats": set(), "artifacts": [], "os": None}}
    for t in a.trivy:
        ctx["cur_file"] = os.path.basename(t)
        parse_trivy(load(t), ctx)
    uz_file = os.path.basename(a.uzomuzo) if a.uzomuzo else None
    sb_file = os.path.basename(a.sbom) if a.sbom else None
    uz_match = {"exact": 0, "by_name": 0, "not_in_sbom": 0, "root": 0}
    uz = load(a.uzomuzo) if a.uzomuzo else {}
    proj = M.project_roots(a.project)
    root_src = {r["name"].lower(): f"{r['manifest']}" + (" (private)" if r.get("private") else "") for r in proj}
    root_src.update({n.lower(): "--root-package" for n in a.root_package})
    root_src.update({n: "Trivy (Relationship=root)" for n in ctx["trivy_roots"] if n not in root_src})
    root_names = set(root_src)
    g = parse_sbom(load(a.sbom), root_names) if a.sbom else None
    sbom_by_name = defaultdict(set)  # (eco, tên) -> {purl_key}: ghép Uzomuzo theo tên khi lệch version
    if g:
        for k, sids in g["by_purl"].items():
            n = g["nodes"][sids[0]]
            if n["eco"] and n["eco"] not in OS_TYPES and sids[0] not in g["project_root_ids"]:
                sbom_by_name[(n["eco"], norm_name(n["name"], n["eco"]))].add(k)
    root_hits = []

    findings, alias = {}, defaultdict(set)

    def upsert(key, name, version, eco=None, purl=None):
        if key not in findings:
            findings[key] = {"key": key, "name": name, "version": version, "ecosystem": eco, "purl": purl,
                             "relation": None, "vulns": [], "uzomuzo": None, "trivy_targets": set()}
        f = findings[key]
        f["ecosystem"] = f["ecosystem"] or eco
        f["purl"] = f["purl"] or purl
        alias[name_key(name, version)].add(key)
        return f

    # 1) Uzomuzo
    for p in uz.get("packages", []):
        pp = parse_purl(p.get("purl"))
        if not pp:
            continue
        if pp["display"].lower() in root_names:
            root_hits.append({"name": pp["display"], "source": "Uzomuzo", "reason": root_src[pp["display"].lower()]})
            uz_match["root"] += 1
            continue
        info = {k: p.get(k) for k in (
            "verdict", "lifecycle", "build_integrity", "archived", "disabled", "overall_score", "stable_version",
            "project_license", "version_license", "reason", "error", "dependent_count", "repo_url", "relation")
            if p.get(k) not in (None, "")}
        key = purl_key(p["purl"])
        alts = sbom_by_name.get((pp["type"], norm_name(pp["display"], pp["type"]))) if g and key not in g["by_purl"] else None
        if alts:  # vòng đời là thông tin cấp dự án → gắn cho (các) version thực có trong image
            for ak in sorted(alts):
                n = g["nodes"][g["by_purl"][ak][0]]
                f = upsert(ak, n["name"], n["version"], n["eco"], n["purl"])
                f["uzomuzo"] = dict(info)
                f["uzomuzo_version"] = pp["version"]
                f.setdefault("found_in", {}).setdefault(uz_file, set()).add(f"packages[] {p['purl']} (ghép theo tên)")
            uz_match["by_name"] += 1
            continue
        f = upsert(key, pp["display"], pp["version"], pp["type"], p["purl"])
        f["uzomuzo"] = info
        f.setdefault("found_in", {}).setdefault(uz_file, set()).add(f"packages[] {p['purl']}")
        if g:
            uz_match["exact" if key in g["by_purl"] else "not_in_sbom"] += 1

    # 2) Trivy
    n_vuln_records = 0
    for v in ctx["vulns"]:
        if not v["pkg"]:
            ctx["others"].append({"check": "vuln-unparsed", "severity": v["severity"], "title": v["id"], "path": v["target"]})
            continue
        n_vuln_records += 1
        key, eco, join = None, None, None
        if v["purl"]:
            key, eco = purl_key(v["purl"]), parse_purl(v["purl"])["type"]
        elif g:
            cands = g["by_name"].get(name_key(v["pkg"], v["installed"]), [])
            typed = [s for s in cands if (g["nodes"][s]["eco"] in OS_TYPES) == v["is_os"]] or cands
            keys = {purl_key(g["nodes"][s]["purl"]) for s in typed if g["nodes"][s]["purl"]}
            if len(keys) == 1:
                key = keys.pop()
                eco = g["nodes"][typed[0]]["eco"]
            elif len(keys) > 1:
                join = "ambiguous"
            else:
                join = "not_in_sbom"
        if not key:
            ks = alias.get(name_key(v["pkg"], v["installed"]))
            key = next(iter(ks)) if ks and len(ks) == 1 else f"name:{norm_name(v['pkg'])}@{v['installed']}"
        f = upsert(key, v["pkg"], v["installed"], eco, v["purl"])
        if join and not f.get("join"):
            f["join"] = join
        if v["is_os"]:
            f["is_os_hint"] = True
        ex = next((x for x in f["vulns"] if x["id"] == v["id"]), None)
        if not ex:
            f["vulns"].append({**{k: v[k] for k in ("id", "severity", "title", "fixed", "fixed_source", "status", "aliases")},
                               "sources": [v["src"]]})
        else:  # cùng CVE từ nguồn khác: bổ sung thông tin còn thiếu
            if v["fixed"] and not ex["fixed"]:
                ex["fixed"], ex["fixed_source"] = v["fixed"], v["fixed_source"]
            ex["status"] = ex["status"] or v["status"]
            if v["src"] not in ex.setdefault("sources", []):
                ex["sources"].append(v["src"])
            if SEV_ORDER.get(v["severity"], 0) > SEV_ORDER.get(ex["severity"], 0):
                ex["severity"] = v["severity"]
        f["trivy_targets"].add(v["target"])
        f.setdefault("found_in", {}).setdefault(v["src"], set()).add(v.get("pkg_path") or v["target"] or "-")
        loc = classify_location(v.get("pkg_path"))
        f.setdefault("vuln_locs", defaultdict(set))[v["id"]].add(loc)
        if v.get("pkg_path") and loc:
            f.setdefault("loc_paths", {}).setdefault(loc, v["pkg_path"])

    # 3) SBOM
    for f in findings.values():
        sids = g["by_purl"].get(f["key"], []) if g else []
        if g and not sids:
            c = g["by_name"].get(name_key(f["name"], f["version"]), [])
            keys = {purl_key(g["nodes"][s]["purl"]) for s in c if g["nodes"][s]["purl"]}
            sids = c if len(keys) <= 1 else []
            if len(keys) > 1:
                f["join"] = f.get("join") or "ambiguous"
        if not sids:
            if g and not f.get("join"):
                f["join"] = "not_in_sbom"
            continue
        n = g["nodes"][sids[0]]
        f["join"] = "sbom"
        f["_sids"] = sids
        f["ecosystem"] = f["ecosystem"] or n["eco"]
        f["purl"] = f["purl"] or n["purl"]
        f["qualifiers"] = n["qualifiers"]
        f["license"] = n["license"]
        if n["eco"] in OS_TYPES:
            m = re.search(r"from:\s*(\S+)(?:\s+(\S+))?", n.get("source") or "")
            f["os_source_name"] = m.group(1) if m else n["name"]
            f["os_source_version"] = m.group(2) if m and m.group(2) else None
        f["sbom"] = dep_info(sids, g)
        f["scope"] = f["sbom"]["scope"]

    # 3b) Cùng package ở nhiều vị trí (vd undici trong app và trong npm của base image) → tách finding:
    #     phương án xử lý khác nhau (lockfile của app vs base image)
    import copy
    for key in list(findings):
        f = findings[key]
        groups = defaultdict(list)
        for s in f.pop("_sids", []):
            groups[sid_location(g, s)].append(s)
        vlocs = {l for ls in (f.get("vuln_locs") or {}).values() for l in ls if l}
        if not groups:
            for l in vlocs:
                groups[l] = []
        if None in groups and len(groups) > 1:
            target = "app" if "app" in groups else next(k for k in groups if k)
            groups[target] += groups.pop(None)
        if len(groups) <= 1:
            loc = next(iter(groups), None) if groups else None
            f["install_location"] = loc
            f["install_path"] = (f.get("loc_paths") or {}).get(loc) or next(
                (g["nodes"][s]["path"] for s in groups.get(loc, []) if g and g["nodes"][s].get("path")), None)
            continue
        del findings[key]
        for loc, sids in groups.items():
            c = copy.deepcopy(f)
            c["key"] = f"{key}#{loc}"
            c["install_location"] = loc
            c["install_path"] = (f.get("loc_paths") or {}).get(loc) or next(
                (g["nodes"][s]["path"] for s in sids if g and g["nodes"][s].get("path")), None)
            vl = f.get("vuln_locs") or {}
            c["vulns"] = [v for v in c["vulns"] if not (vl.get(v["id"], set()) - {None}) or loc in vl.get(v["id"], set())]
            if g and sids:
                c["sbom"] = dep_info(sids, g)
                c["scope"] = c["sbom"]["scope"]
            findings[c["key"]] = c
    for f in findings.values():
        f.pop("vuln_locs", None)
        f.pop("loc_paths", None)
        fi = f.setdefault("found_in", {})
        if f.get("install_location"):
            for fn in list(fi):
                if fn not in (uz_file, sb_file):
                    keep = {x for x in fi[fn] if classify_location(x) in (None, f["install_location"])}
                    fi[fn] = keep or fi[fn]
        if f.get("sbom") and sb_file:
            sb = f["sbom"]
            fi[sb_file] = {f.get("install_path") or ", ".join(sb.get("locations") or []) or
                           ("gói hệ điều hành" if f.get("ecosystem") in OS_TYPES else "có trong SBOM")}

    # 4) Quan hệ direct/transitive: SBOM tường minh > Trivy > Uzomuzo > SBOM suy luận; mâu thuẫn thì ghi lại
    for f in findings.values():
        f["kind"] = "os" if f["ecosystem"] in OS_TYPES or f.pop("is_os_hint", False) else "app"
        f["trivy_targets"] = sorted(f["trivy_targets"])
        tp = ctx["trivy_pkgs"].get(f["key"].split("#")[0], {})
        if tp.get("dev"):
            f["scope"] = "dev"
        if f["kind"] == "os" or f.get("install_location") in IMAGE_LOCS:
            f["relation"], f["relation_basis"] = None, None
            continue
        sb = f.get("sbom") or {}
        cand = [(sb.get("relation_sbom"), "SBOM") if sb.get("relation_basis") == "sbom" else (None, None),
                (tp.get("relation"), "Trivy"), ((f.get("uzomuzo") or {}).get("relation"), "Uzomuzo"),
                (sb.get("relation_sbom"), "SBOM (suy luận)") if sb.get("relation_basis") == "sbom-inferred" else (None, None)]
        cand = [c for c in cand if c[0]]
        f["relation"], f["relation_basis"] = cand[0] if cand else (None, None)
        explicit = {c[0] for c in cand if c[1] != "SBOM (suy luận)"}
        if len(explicit) > 1:
            f["relation_conflict"] = " / ".join(f"{s}: {r}" for r, s in cand) + " → kiểm tra lockfile (npm ls / go mod why ...)"

    # 5) Ngữ cảnh ngoài: OSV, KEV, EPSS, endoflife.date
    status = {}
    if a.osv or a.online:
        status["osv"] = enrich_osv(findings, osv_query_fn or osv_query, a.private_pattern)
    all_cves = {i for f in findings.values() for v in f["vulns"] for i in [v["id"]] + v.get("aliases", [])}
    ctx["kev"] = load_kev(a.kev, a.online, status)
    ctx["epss"] = load_epss(a.epss, all_cves, a.online, status)
    eol_cache, eol_status_ = {}, {}
    platform, eol_candidates = [], []
    os_node = next((n for n in g["nodes"].values() if n["purpose"] == "OPERATING-SYSTEM"), None) if g else None
    os_name = f"{os_node['name']} {os_node['version']}" if os_node else (
        f"{ctx['trivy_info']['os']['family']} {ctx['trivy_info']['os']['name']}" if ctx["trivy_info"]["os"] else None)
    if ctx["trivy_info"]["os"] and ctx["trivy_info"]["os"]["eosl"]:
        platform.append({"name": os_name, "is_eol": True, "source": "Trivy (EOSL)"})
    os_prod = OS_PRODUCTS.get((os_node or {}).get("name", "").lower()) if os_node else None
    runtimes = []
    if g:
        for n in g["nodes"].values():
            for rx, prod in RUNTIME_PRODUCTS:
                if n["name"] and rx.match(n["name"]) and n["version"]:
                    runtimes.append((prod, n["name"], n["version"]))
    checks = ([(os_prod, os_name, os_node["version"])] if os_prod else []) + runtimes
    lib_checks = []
    if g:
        for n in g["nodes"].values():
            prod = EOL_PRODUCTS.get((n["eco"], norm_name(n["name"], n["eco"]))) if n["eco"] else None
            if prod and n["purl"]:
                lib_checks.append((prod, n))
    if a.online:
        for prod, label, ver in checks:
            r = eol_lookup(prod, ver, eol_cache, eol_status_, today)
            if r:
                platform.append({"name": label if label == os_name else f"{label} {ver}", **r})
        for prod, n in lib_checks:
            r = eol_lookup(prod, n["version"], eol_cache, eol_status_, today)
            if r and r["is_eol"]:
                f = upsert(purl_key(n["purl"]), n["name"], n["version"], n["eco"], n["purl"])
                f["eol_info"] = r
                if "sbom" not in f:
                    f.update({"join": "sbom", "kind": "app", "trivy_targets": [], "qualifiers": n["qualifiers"],
                              "sbom": dep_info(g["by_purl"][purl_key(n["purl"])], g)})
                    f["scope"] = f["sbom"]["scope"]
                    f["relation"] = f["sbom"]["relation_sbom"]
                    f["relation_basis"] = "SBOM"
        status["eol"] = f"{len(eol_cache)} sản phẩm" + (f", lỗi {eol_status_['errors']}" if eol_status_.get("errors") else "")
    else:
        eol_candidates = [{"product": p, "name": l, "version": v} for p, l, v in checks] + \
                         [{"product": p, "name": n["name"], "version": n["version"]} for p, n in lib_checks]

    for f in findings.values():
        evaluate(f, ctx)

    rank = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, None: 9}
    out = sorted(findings.values(), key=lambda f: (rank[f["suggested_priority"]], -SEV_ORDER.get(f["max_severity"] or "", 0),
                                                  -f.get("active_vulns", 0), f["name"]))
    flagged = [f for f in out if f["suggested_priority"]]
    suppressed = [{"name": f["name"], "version": f["version"], "ids": f["suppressed"]} for f in out if f["suppressed"]]

    # Gom gói OS theo source package
    groups = {}
    for f in flagged:
        if f["kind"] != "os" or not f["active_vulns"]:
            continue
        src = f.get("os_source_name") or f["name"]
        gp = groups.setdefault(src, {"source": src, "packages": [], "vuln_ids": set(), "max_severity": None,
                                     "targets": set(), "priority": "P4", "has_unfixed": False})
        gp["packages"].append(f"{f['name']}@{f['version']}")
        gp["vuln_ids"].update(v["id"] for v in f["vulns"] if v["applicability"] != "Không áp dụng")
        if not gp["max_severity"] or SEV_ORDER[f["max_severity"]] > SEV_ORDER[gp["max_severity"]]:
            gp["max_severity"] = f["max_severity"]
        if f["target_version"]:
            gp["targets"].add(f["target_version"])
        gp["has_unfixed"] |= bool(f["unfixed_ids"])
        gp["priority"] = min(gp["priority"], f["suggested_priority"], key=lambda x: rank[x])
        f["os_group"] = src
    os_groups = sorted(({**gp, "vuln_ids": sorted(gp["vuln_ids"]), "vuln_count": len(gp["vuln_ids"]),
                         "targets": V.sort_versions(gp["targets"], "deb")} for gp in groups.values()),
                       key=lambda x: (rank[x["priority"]], -SEV_ORDER[x["max_severity"]]))

    # 6) Độ phủ dữ liệu - giới hạn của phân tích
    warnings = []
    have_t, have_u, have_s = bool(a.trivy), bool(a.uzomuzo), bool(a.sbom)
    if not have_t:
        warnings.append("Không có dữ liệu lỗ hổng (Trivy) → không kết luận được thư viện nào không có CVE")
    if not have_u:
        warnings.append("Không có Uzomuzo → chưa đánh giá vòng đời/bảo trì của thư viện")
    if not have_s:
        warnings.append("Không có SBOM → không xác định được quan hệ phụ thuộc, scope dev/runtime")
    act = [v for f in findings.values() for v in f["vulns"] if v.get("applicability") != "Không áp dụng"]
    nofix_info = [v for v in act if v["fix_state"] == "chưa rõ"]
    if act and nofix_info:
        warnings.append(f"{len(nofix_info)}/{len(act)} CVE chưa có thông tin bản vá"
                        + (" (Trivy dạng code-quality không có fixed version)" if ctx["trivy_info"]["formats"] == {"codequality"} else ""))
    if ctx["kev"] is None and ctx["epss"] is None and act:
        warnings.append("Chưa đối chiếu CISA KEV/EPSS → mức ưu tiên dựa trên severity, là tạm thời")
    sb_digest = sb_name = None
    if g:
        ctr = next((n for n in g["nodes"].values() if n["purpose"] == "CONTAINER"), None)
        sb_name = (ctr or {}).get("raw_name") or g["doc"].get("name")
        if ctr and ctr.get("version") and "sha256" in str(ctr["version"]):
            sb_digest = ctr["version"]
    t_names = {image_ref(x["name"]) for x in ctx["trivy_info"]["artifacts"] if x.get("name")}
    t_digests = {d.split("@")[-1] for x in ctx["trivy_info"]["artifacts"] for d in x.get("digests", [])}  # RepoDigests
    t_image_ids = {x["image_id"] for x in ctx["trivy_info"]["artifacts"] if x.get("image_id")}           # config digest
    if sb_digest and (t_digests or t_image_ids):
        source_match = "khớp" if (sb_digest in t_digests or sb_digest in t_image_ids) else "không khớp"
        match_basis = "digest"
    elif image_ref(sb_name) and t_names:
        source_match = "khớp" if image_ref(sb_name) in t_names else "không khớp"
        match_basis = "tên image:tag (chưa có digest)"
    else:
        source_match, match_basis = "chưa xác minh", None
    if source_match == "không khớp":
        warnings.append(f"SBOM ({sb_name}) và Trivy ({', '.join(sorted(n for n in t_names if n))}) có thể không cùng artifact")
    dep_digest = (a.deployed_digest or "").split("@")[-1] or None
    known = [d for d in (dep_digest, sb_digest, next(iter(sorted(t_digests)), None)) if d]
    if source_match == "không khớp" or (dep_digest and ((sb_digest and dep_digest != sb_digest) or
                                                          (t_digests and dep_digest not in t_digests))):
        triple = "không khớp"
    elif dep_digest and sb_digest and t_digests and dep_digest == sb_digest and dep_digest in t_digests:
        triple = "khớp"
    else:
        triple = "chưa xác minh"
    if dep_digest and triple == "không khớp":
        warnings.insert(0, "Digest image đang chạy khác digest đã quét → kết quả có thể không phản ánh môi trường thật")
    artifact_identity = {
        "environment": a.environment, "source_revision": a.revision, "deployed_image": a.deployed_image,
        "deployed_digest": dep_digest, "trivy_target_digest": sorted(t_digests) or None, "trivy_image_id": sorted(t_image_ids) or None,
        "sbom_image_digest": sb_digest, "trivy_vs_sbom": source_match, "trivy_vs_sbom_basis": match_basis,
        "trivy_sbom_deployment": triple,
        "trivy_scan_time": min((x["created"] for x in ctx["trivy_info"]["artifacts"] if x.get("created")), default=None),
        "sbom_created": (g["doc"].get("creationInfo") or {}).get("created") if g else None}
    report_status = "Verified" if triple == "khớp" else "Preliminary"
    not_in_sbom = sum(1 for f in findings.values() if f.get("join") == "not_in_sbom")
    if not_in_sbom:
        warnings.append(f"{not_in_sbom} package Trivy báo nhưng không có trong SBOM")
    # Độ phủ theo từng package: chỉ đếm "không phát hiện vấn đề" khi package có CẢ dữ liệu lỗ hổng lẫn vòng đời
    base_key = lambda k: k.split("#")[0]
    life_keys = {base_key(f["key"]) for f in findings.values() if f.get("uzomuzo")}
    flagged_keys = {base_key(f["key"]) for f in flagged}
    if g:
        universe = {k: g["nodes"][sids[0]] for k, sids in g["by_purl"].items()
                    if g["nodes"][sids[0]]["purpose"] not in ROOT_PURPOSES and not (set(sids) & g["project_root_ids"])}
        app_universe = {k for k, n in universe.items() if n["eco"] not in OS_TYPES}
        vuln_cov = set(universe) if (have_t and source_match != "không khớp") else set()
    else:
        universe = {base_key(f["key"]): None for f in findings.values()} | {k: None for k in ctx["trivy_pkgs"]}
        app_universe = {k for k in universe if not k.split("/")[0] in OS_TYPES}
        vuln_cov = set(ctx["trivy_pkgs"]) | {base_key(f["key"]) for f in findings.values() if f["vulns"]} if have_t else set()
    life_cov = life_keys & app_universe
    fully = vuln_cov & life_cov
    no_findings = len(fully - flagged_keys) if fully else None
    uz_mismatch = sum(1 for f in findings.values() if f.get("uzomuzo_version"))
    if have_u and app_universe and len(life_cov) < len(app_universe):
        warnings.append(f"Uzomuzo đánh giá {len(life_cov)}/{len(app_universe)} package ứng dụng trong SBOM"
                        + (" → không kết luận 'không phát hiện vấn đề'" if not life_cov else ""))
    if uz_mismatch:
        warnings.append(f"{uz_mismatch} package: Uzomuzo đánh giá version khác với image (ghép theo tên) → Uzomuzo có thể quét source thay vì image")
    if root_hits:
        warnings.append(f"Đã loại project gốc khỏi danh sách thư viện: {', '.join(sorted({r['name'] for r in root_hits}))}")
    img_loc = sum(1 for f in flagged if f.get("install_location") in IMAGE_LOCS)
    if img_loc:
        warnings.append(f"{img_loc} finding nằm trong base image/công cụ toàn cục (vd npm), không thuộc lockfile của app → xử lý ở base image")
    sm = uz.get("summary") or {}
    if uz.get("shown") and sm.get("total") and uz["shown"] < sm["total"]:
        warnings.append(f"Uzomuzo chỉ hiển thị {uz['shown']}/{sm['total']} package")
    times = [parse_time((g["doc"].get("creationInfo") or {}).get("created")) if g else None] + \
            [parse_time(x.get("created")) for x in ctx["trivy_info"]["artifacts"]]
    times = [t for t in times if t]
    if times:
        age = (dt.datetime.fromisoformat(today + "T00:00:00+00:00") - min(times)).days
        if age > 30:
            warnings.append(f"Dữ liệu quét đã {age} ngày → nên quét lại trước khi quyết định")
    if not a.online and eol_candidates:
        warnings.append("Chưa tra endoflife.date cho OS/runtime/framework → xem meta.eol_candidates")

    coverage = {"sources": {"trivy": sorted(ctx["trivy_info"]["formats"]) or False, "uzomuzo": have_u, "sbom": have_s,
                            "kev": ctx["kev"] is not None, "epss": ctx["epss"] is not None,
                            "osv": status.get("osv", False), "eol": status.get("eol", False), "source_code": False},
                "fetch_status": {k: v for k, v in status.items() if k in ("kev", "epss")},
                "artifact": {"sbom": sb_name, "sbom_digest": sb_digest, "trivy": sorted(n for n in t_names if n),
                             "trivy_digests": sorted(t_digests)},
                "source_match": source_match, "scan_time": min(times).isoformat() if times else None, "warnings": warnings,
                "packages": {"total": len(universe), "app": len(app_universe), "vuln_covered": len(vuln_cov),
                             "lifecycle_covered": len(life_cov), "fully_covered": len(fully)}}
    meta = {"artifact": sb_name or next(iter(sorted(n for n in t_names if n)), None), "os": os_name,
            "report_status_suggested": report_status, "artifact_identity": artifact_identity,
            "root_packages": [{"name": n, "source": src} for n, src in sorted(root_src.items())], "root_hits": root_hits,
            "platform_eol": platform, "eol_candidates": eol_candidates,
            "inputs": {"trivy_vuln_records": n_vuln_records, "trivy_other": len(ctx["others"]),
                       "uzomuzo_packages": len(uz.get("packages", [])), "sbom_packages": len(g["nodes"]) if g else 0},
            "coverage": coverage}
    sev = defaultdict(int)
    for f in flagged:
        if f.get("os_group") and f["os_group"] != f["name"]:
            continue
        for v in f["vulns"]:
            if v["applicability"] != "Không áp dụng":
                sev[v["severity"]] += 1
    # Cách đếm: record của scanner ≠ vulnerability duy nhất (cần chuẩn hoá alias CVE/GHSA/OSV)
    active_v = [(f, v) for f in flagged for v in f["vulns"] if v["applicability"] != "Không áp dụng"]
    parent = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for _, v in active_v:
        for al in v.get("aliases", []):
            parent[find(al)] = find(v["id"])
        find(v["id"])
    normalized = bool(active_v) and all(v.get("aliases") or v.get("alias_checked") for _, v in active_v)
    counting = {"scanner_records": n_vuln_records,
                "distinct_ids": len({v["id"] for _, v in active_v}),
                "unique_vulnerabilities": len({find(v["id"]) for _, v in active_v}) if normalized else None,
                "alias_normalized": normalized,
                "affected_packages": len({(f["name"], f["version"], f.get("install_location")) for f, _ in active_v}),
                "advisories_without_id": sum(1 for o in ctx["others"] if o.get("advisory_without_id"))}
    result = {
        "meta": meta,
        "stats": {"cve_by_severity": dict(sev),
                  "by_priority": {p: sum(1 for f in flagged if f["suggested_priority"] == p) for p in ("P1", "P2", "P3", "P4")},
                  "rows_by_priority": {p: sum(1 for f in flagged if f["suggested_priority"] == p and not f.get("os_group"))
                                       + sum(1 for x in os_groups if x["priority"] == p) for p in ("P1", "P2", "P3", "P4")},
                  "by_decision": {d: sum(1 for f in flagged if f["decision"] == d) for d in ("Cần xử lý", "Cần xác minh", "Theo dõi")},
                  "no_findings": no_findings, "no_findings_basis": f"{len(fully)} package có đủ dữ liệu lỗ hổng + vòng đời",
                  "suppressed_cves": sum(len(s["ids"]) for s in suppressed), "counting": counting},
        "findings": flagged, "os_groups": os_groups, "suppressed": suppressed, "other_issues": ctx["others"]}
    for f in out:
        f["found_in"] = [{"file": fn, "locations": sorted(locs)[:5]} for fn, locs in sorted((f.get("found_in") or {}).items(), key=lambda x: str(x[0]))]

    # Số liệu quét theo từng file input
    input_files = []
    for t in a.trivy:
        fn = os.path.basename(t)
        recs = [v for v in ctx["vulns"] if v.get("src") == fn]
        oth = [o for o in ctx["others"] if o.get("src") == fn]
        sevc = defaultdict(int)
        for v in recs:
            sevc[v["severity"]] += 1
        oc = defaultdict(int)
        for o in oth:
            oc[o["check"]] += 1
        input_files.append({
            "file": fn, "kind": ctx.get("file_format", {}).get(fn, "Trivy"),
            "records": len(recs), "distinct_ids": len({v["id"] for v in recs}),
            "packages": len({(v["pkg"], v["installed"]) for v in recs if v["pkg"]}),
            "by_severity": dict(sevc), "with_fixed_version": sum(1 for v in recs if v["fixed"]),
            "with_status": sum(1 for v in recs if v.get("status")), "other_issues": dict(oc),
            "targets": sorted({v["target"] for v in recs if v["target"]})[:5],
            "flagged": sum(1 for f in flagged if any(x["file"] == fn for x in f["found_in"]))})
    if a.uzomuzo:
        vc = defaultdict(int)
        for p_ in uz.get("packages", []):
            vc[p_.get("verdict") or "-"] += 1
        input_files.append({"file": uz_file, "kind": "Uzomuzo", "entries": len(uz.get("packages", [])), "by_verdict": dict(vc),
                            "summary": uz.get("summary"), "sbom_match": uz_match if g else None,
                            "flagged": sum(1 for f in flagged if any(x["file"] == uz_file for x in f["found_in"]))})
    if g:
        pc = defaultdict(int)
        for n in g["nodes"].values():
            pc[n["purpose"] or "-"] += 1
        input_files.append({"file": sb_file, "kind": f"SBOM {g['doc'].get('spdxVersion', 'SPDX')}", "artifact": sb_name, "digest": sb_digest,
                            "created": (g["doc"].get("creationInfo") or {}).get("created"), "packages_total": len(g["nodes"]),
                            "app_packages": len(app_universe), "os_packages": sum(1 for k in universe if k.split("/")[0] in OS_TYPES),
                            "by_purpose": dict(pc), "relationships": len(g["doc"].get("relationships", [])),
                            "dependency_edges": sum(len(v) for v in g["dep_children"].values()),
                            "project_roots_excluded": len(g["project_root_ids"]),
                            "flagged": sum(1 for f in flagged if any(x["file"] == sb_file for x in f["found_in"]))})
    for flag, kind, data_ in (("kev", "CISA KEV", ctx["kev"]), ("epss", "EPSS", ctx["epss"])):
        if getattr(a, flag):
            input_files.append({"file": os.path.basename(getattr(a, flag)), "kind": kind, "entries": len(data_ or {})})
    result["meta"]["input_files"] = input_files
    with open(a.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=1, default=list)

    # ---- digest
    st = result["stats"]
    print(f"Artifact: {meta['artifact']} | OS: {os_name} | Trivy↔SBOM: {source_match}"
          f" | Trivy↔SBOM↔deployment: {triple} | Trạng thái gợi ý: {report_status}")
    if root_src:
        print(f"Project gốc (không tính là thư viện): {', '.join(f'{n} [{s}]' for n, s in sorted(root_src.items()))}")
    print(f"Nguồn: {json.dumps(coverage['sources'], ensure_ascii=False, default=str)}")
    for w in warnings:
        print(f"⚠ {w}")
    print(f"Ưu tiên (hàng bảng): {st['rows_by_priority']} | Quyết định: {st['by_decision']} | "
          f"không phát hiện vấn đề: {f'{no_findings}/{len(fully)} package đủ dữ liệu' if no_findings is not None else 'không kết luận (thiếu nguồn)'} | "
          f"CVE không áp dụng (vendor): {st['suppressed_cves']}")
    for x in result["meta"]["input_files"]:
        extra = {k: v for k, v in x.items() if k not in ("file", "kind", "targets", "summary")}
        print(f"[File] {x['file']} ({x['kind']}): {json.dumps(extra, ensure_ascii=False, default=str)}")
    c = st["counting"]
    print(f"Đếm: {c['scanner_records']} record · {c['distinct_ids']} ID · unique sau chuẩn hoá alias: "
          f"{c['unique_vulnerabilities'] if c['unique_vulnerabilities'] is not None else 'chưa xác định'} · "
          f"{c['affected_packages']} package bị ảnh hưởng · advisory thiếu ID: {c['advisories_without_id']}")
    shown = 0
    for f in flagged:
        if f.get("os_group") and f["os_group"] != f["name"] and any(x["source"] == f["os_group"] for x in os_groups):
            continue
        shown += 1
        if shown > 40:
            print(f"... xem thêm trong {a.output}")
            break
        tgt = f"→ {f['target_version']} ({f['upgrade_type']}, {f['fix_summary']}, {'/'.join(f['target_source'] or [])})" if f["target_version"] else \
            (f"→ ? ({f['fix_coverage']})" if f["active_vulns"] else "")
        rel = f"{f['relation'] or '-'}/{f['scope_display']}"
        print(f"[{f['suggested_priority']}|{f['decision']}] {f['section']:4} {f['kind']:3} {f['name']}@{f['version']} {rel} {tgt} "
              f"| {'; '.join(f['priority_basis'])}" + (f" | EOL: {', '.join(f['eol_basis'])}" if f["eol_basis"] else "")
              + (f" | ➜ {f['remediation_hint']}" if f.get("install_location") in IMAGE_LOCS else "")
              + (" | ⚠ " + "; ".join(f["verify"]) if f["verify"] else ""))
    for gp in os_groups:
        print(f"[OS {gp['priority']}] {gp['source']}: {len(gp['packages'])} gói, {gp['vuln_count']} CVE, max {gp['max_severity']}, đích {gp['targets'] or '-'}")
    for p in platform:
        print(f"[Nền tảng] {p['name']}: {'HẾT HỖ TRỢ' if p['is_eol'] else 'còn hỗ trợ'} ({p['source']})")
    if ctx["others"]:
        kinds = defaultdict(int)
        for o in ctx["others"]:
            kinds[o["check"]] += 1
        print(f"Issue không phải CVE: {dict(kinds)}")
    print(f"→ Đã ghi {a.output}")
    return result


if __name__ == "__main__":
    main()
