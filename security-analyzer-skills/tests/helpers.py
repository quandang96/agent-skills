"""Tiện ích dựng dữ liệu kiểm thử tối giản (không phải dữ liệu quét thật)."""
import atexit
import contextlib
import io
import shutil
import json
import os
import sys
import tempfile

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, SCRIPTS)

import aggregate  # noqa: E402
import find_usage  # noqa: E402

_TMP = []
_mkdtemp = tempfile.mkdtemp


def _tracked_mkdtemp(*a, **kw):
    d = _mkdtemp(*a, **kw)
    _TMP.append(d)
    return d


tempfile.mkdtemp = _tracked_mkdtemp  # dọn thư mục tạm của test khi kết thúc
atexit.register(lambda: [shutil.rmtree(d, ignore_errors=True) for d in _TMP])


def native_vuln(vid, pkg, ver, fixed="", sev="HIGH", status=None, purl=None, eco="npm"):
    return {"VulnerabilityID": vid, "PkgName": pkg, "InstalledVersion": ver, "FixedVersion": fixed, "Severity": sev,
            "Status": status, "PkgIdentifier": {"PURL": purl or f"pkg:{eco}/{pkg}@{ver}"}, "Title": f"{pkg} issue"}


def native(vulns, target="app/package-lock.json", cls="lang-pkgs", packages=None, **top):
    return {"SchemaVersion": 2, **top,
            "Results": [{"Target": target, "Class": cls, "Vulnerabilities": vulns, "Packages": packages or []}]}


def cq_issue(vid, pkg, ver, sev="major", path="app/package-lock.json"):
    return {"type": "issue", "check_name": "container_scanning", "categories": ["Security"],
            "description": f"{vid} - {pkg} - {ver} - {pkg} issue", "fingerprint": vid + pkg,
            "content": "CVE description", "severity": sev, "location": {"path": path, "lines": {"begin": 0}}}


def spdx_pkg(sid, name, ver=None, purl=None, purpose="LIBRARY", source=None, ann=None):
    p = {"SPDXID": sid, "name": name, "versionInfo": ver, "primaryPackagePurpose": purpose,
         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}] if purl else [],
         "annotations": [{"comment": f"{k}: {v}"} for k, v in (ann or {}).items()]}
    if source:
        p["sourceInfo"] = source
    return p


def rel(a, b, t):
    return {"spdxElementId": a, "relatedSpdxElement": b, "relationshipType": t}


def sbom(packages, relationships, name="registry.example.com/team/app:1.0"):
    return {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": name,
            "creationInfo": {"created": "2026-11-01T00:00:00Z"}, "packages": packages, "relationships": relationships, "files": []}


def run(trivy_files=(), uzomuzo=None, sbom_doc=None, extra=None, osv_query_fn=None, http_fn=None, today="2026-11-08",
        keep_dir=False):
    """Chạy aggregate.main trong thư mục tạm. trivy_files: danh sách nội dung các file Trivy."""
    d = tempfile.mkdtemp()
    argv = ["-o", os.path.join(d, "out.json"), "--today", today]
    for i, t in enumerate(trivy_files):
        p = os.path.join(d, f"trivy{i}.json")
        with open(p, "w") as fh:
            json.dump(t, fh)
        argv += ["--trivy", p]
    for flag, obj in (("--uzomuzo", uzomuzo), ("--sbom", sbom_doc)):
        if obj is not None:
            p = os.path.join(d, flag[2:] + ".json")
            with open(p, "w") as fh:
                json.dump(obj, fh)
            argv += [flag, p]
    argv += extra or []
    with contextlib.redirect_stdout(io.StringIO()):
        res = aggregate.main(argv, osv_query_fn=osv_query_fn, http_fn=http_fn)
    return (res, os.path.join(d, "out.json")) if keep_dir else res


def finding(result, name):
    return next(f for f in result["findings"] if f["name"] == name)
