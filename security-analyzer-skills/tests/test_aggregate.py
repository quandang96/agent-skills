"""Kiểm thử aggregate.py - mỗi test ứng với một rủi ro đã biết (xem tên test)."""
import json
import os
import tempfile
import unittest

from helpers import cq_issue, finding, native, native_vuln, rel, run, sbom, spdx_pkg


def uz_pkg(purl, verdict="ok", lifecycle="Active", relation="direct", **kw):
    return {"purl": purl, "verdict": verdict, "lifecycle": lifecycle, "build_integrity": "Moderate", "archived": False,
            "disabled": False, "overall_score": 6, "relation": relation, **kw}


class TestApplicability(unittest.TestCase):
    def test_not_affected_is_not_actionable(self):
        r = run([native([native_vuln("CVE-2099-0001", "a", "1.0.0", sev="CRITICAL", status="not_affected")])])
        self.assertFalse([f for f in r["findings"] if f["name"] == "a"])
        self.assertEqual(r["stats"]["suppressed_cves"], 1)

    def test_under_investigation_needs_verification(self):
        r = run([native([native_vuln("CVE-2099-0002", "a", "1.0.0", sev="CRITICAL", status="under_investigation")])])
        self.assertEqual(finding(r, "a")["decision"], "Cần xác minh")

    def test_end_of_life_status_is_possible_not_confirmed(self):
        r = run([native([native_vuln("CVE-2099-0003", "a", "1.0.0", sev="HIGH", status="end_of_life")])])
        f = finding(r, "a")
        self.assertEqual(f["vulns"][0]["applicability"], "Có thể")
        self.assertTrue(any("end_of_life" in x for x in f["verify"]))

    def test_os_will_not_fix_not_downgraded(self):
        v = native_vuln("CVE-2099-0004", "libx", "1.0-1", sev="HIGH", status="will_not_fix",
                        purl="pkg:deb/debian/libx@1.0-1?distro=debian-12.5")
        f = finding(run([native([v], target="img:1 (debian 12.5)", cls="os-pkgs")]), "libx")
        self.assertEqual(f["suggested_priority"], "P2")
        self.assertEqual(f["decision"], "Cần xử lý")
        self.assertEqual(f["fix_coverage"], "none")


class TestFixSelection(unittest.TestCase):
    def test_partial_fix_is_reported(self):
        r = run([native([native_vuln("CVE-2099-0010", "a", "1.0.0", "1.0.5"), native_vuln("CVE-2099-0011", "a", "1.0.0", "")])])
        f = finding(r, "a")
        self.assertEqual(f["target_version"], "1.0.5")
        self.assertEqual(f["fix_coverage"], "partial")
        self.assertEqual(f["fix_summary"], "vá 1/2 CVE")
        self.assertIn("CVE-2099-0011", f["unfixed_ids"])

    def test_branch_aware_target(self):
        r = run([native([native_vuln("CVE-2099-0020", "qs", "6.7.0", "6.7.3, 6.8.3"), native_vuln("CVE-2099-0021", "qs", "6.7.0", "6.8.1")])])
        f = finding(r, "qs")
        self.assertEqual(f["target_version"], "6.8.3", "6.8.1 vẫn dính CVE-2099-0020 (nhánh 6.8 cần 6.8.3)")
        self.assertEqual(f["fix_coverage"], "full")

    def test_major_alternative(self):
        r = run([native([native_vuln("CVE-2099-0030", "axios", "0.21.1", "0.21.2"), native_vuln("CVE-2099-0031", "axios", "0.21.1", "1.6.0")])])
        f = finding(r, "axios")
        self.assertEqual((f["target_version"], f["upgrade_type"]), ("1.6.0", "major"))
        self.assertEqual(f["same_major_target"], "0.21.2")
        self.assertEqual(f["same_major_leaves_unfixed"], ["CVE-2099-0031"])

    def test_debian_epoch(self):
        v = native_vuln("CVE-2099-0040", "liby", "1:1.0-1", "1:1.5-1", purl="pkg:deb/debian/liby@1:1.0-1?distro=debian-12")
        f = finding(run([native([v], target="img (debian 12)", cls="os-pkgs")]), "liby")
        self.assertEqual(f["target_version"], "1:1.5-1")
        self.assertEqual(f["fix_coverage"], "full")

    def test_stable_version_never_used_as_fix(self):
        r = run([[cq_issue("CVE-2099-0050", "a", "1.0.0")]], uzomuzo={"packages": [uz_pkg("pkg:npm/a@1.0.0", stable_version="9.9.9")]})
        f = finding(r, "a")
        self.assertIsNone(f["target_version"])
        self.assertEqual(f["latest_stable"], "9.9.9")

    def test_osv_fills_missing_fix_and_ranges(self):
        def fake(name, version, eco):
            return [{"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2099-0060"], "affected": [{"package": {"name": "a", "ecosystem": "npm"},
                     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}]}]}]
        doc = sbom([spdx_pkg("A", "app", purpose="APPLICATION"), spdx_pkg("L", "a", "1.0.0", "pkg:npm/a@1.0.0")], [rel("A", "L", "DEPENDS_ON")])
        r = run([[cq_issue("CVE-2099-0060", "a", "1.0.0")]], sbom_doc=doc, extra=["--osv"], osv_query_fn=fake)
        f = finding(r, "a")
        self.assertEqual((f["target_version"], f["target_source"]), ("1.2.0", ["OSV"]))
        self.assertIn("GHSA-xxxx-yyyy-zzzz", f["vulns"][0]["aliases"])


class TestIdentityAndGraph(unittest.TestCase):
    def test_distro_qualifier_keeps_packages_apart(self):
        v1 = native_vuln("CVE-2099-0070", "openssl", "3.0.1", "3.0.2", purl="pkg:deb/debian/openssl@3.0.1?distro=debian-11")
        v2 = native_vuln("CVE-2099-0070", "openssl", "3.0.1", "3.0.3", purl="pkg:deb/debian/openssl@3.0.1?distro=debian-12")
        r = run([native([v1], cls="os-pkgs"), native([v2], cls="os-pkgs")])
        self.assertEqual(len([f for f in r["findings"] if f["name"] == "openssl"]), 2)

    def _graph(self):
        pk = [spdx_pkg("C", "registry.example.com/team/app:1.0", purpose="CONTAINER"),
              spdx_pkg("A1", "web/package-lock.json", purpose="APPLICATION"),
              spdx_pkg("A2", "worker/package-lock.json", purpose="APPLICATION"),
              spdx_pkg("A3", "tools/package-lock.json", purpose="APPLICATION"),
              spdx_pkg("X1", "x", "1.0.0", "pkg:npm/x@1.0.0"), spdx_pkg("Y1", "y", "1.0.0", "pkg:npm/y@1.0.0"),
              spdx_pkg("Y2", "y", "1.0.0", "pkg:npm/y@1.0.0"), spdx_pkg("O", "orphan", "1.0.0", "pkg:npm/orphan@1.0.0"),
              spdx_pkg("D", "devtool", "1.0.0", "pkg:npm/devtool@1.0.0"), spdx_pkg("DT", "devchild", "1.0.0", "pkg:npm/devchild@1.0.0")]
        rs = [rel("C", "A1", "CONTAINS"), rel("C", "A2", "CONTAINS"), rel("C", "A3", "CONTAINS"),
              rel("A1", "X1", "CONTAINS"), rel("A1", "Y1", "CONTAINS"), rel("A2", "Y2", "CONTAINS"), rel("A3", "O", "CONTAINS"),
              rel("A1", "D", "CONTAINS"), rel("A1", "DT", "CONTAINS"),
              rel("X1", "Y1", "DEPENDS_ON"), rel("D", "A1", "DEV_DEPENDENCY_OF"), rel("D", "DT", "DEPENDS_ON")]
        return sbom(pk, rs)

    def _vulns(self, *names):
        return [native([native_vuln(f"CVE-2099-{100 + i}", n, "1.0.0", "1.0.1", sev="CRITICAL") for i, n in enumerate(names)])]

    def test_multiple_locations_merged(self):
        f = finding(run(self._vulns("y"), sbom_doc=self._graph()), "y")
        self.assertEqual(f["sbom"]["occurrences"], 2)
        self.assertEqual(f["sbom"]["locations"], ["web/package-lock.json", "worker/package-lock.json"])
        self.assertEqual(f["relation"], "transitive")

    def test_orphan_without_graph_is_unknown(self):
        f = finding(run(self._vulns("orphan"), sbom_doc=self._graph()), "orphan")
        self.assertIsNone(f["relation"])

    def test_graph_root_is_inferred_direct(self):
        f = finding(run(self._vulns("x"), sbom_doc=self._graph()), "x")
        self.assertEqual((f["relation"], f["relation_basis"]), ("direct", "SBOM (suy luận)"))

    def test_dev_dependency_scope_lowers_priority(self):
        r = run(self._vulns("devtool", "devchild"), sbom_doc=self._graph())
        for n in ("devtool", "devchild"):
            f = finding(r, n)
            self.assertEqual(f["scope"], "dev", n)
            self.assertEqual(f["suggested_priority"], "P2", n)
            self.assertIn("chỉ dùng cho dev", f["priority_basis"])

    def test_relation_conflict_reported(self):
        t = native([native_vuln("CVE-2099-0080", "a", "1.0.0", "1.0.1")],
                   packages=[{"Name": "a", "Version": "1.0.0", "Identifier": {"PURL": "pkg:npm/a@1.0.0"}, "Relationship": "indirect"}])
        f = finding(run([t], uzomuzo={"packages": [uz_pkg("pkg:npm/a@1.0.0", relation="direct")]}), "a")
        self.assertIn("Trivy: transitive", f["relation_conflict"])


class TestPriority(unittest.TestCase):
    def test_high_direct_with_fix_is_p2_without_exploit_context(self):
        f = finding(run([native([native_vuln("CVE-2099-0090", "a", "1.0.0", "1.0.1")])],
                        uzomuzo={"packages": [uz_pkg("pkg:npm/a@1.0.0")]}), "a")
        self.assertEqual(f["suggested_priority"], "P2")
        self.assertEqual(f["exploit_context"], "chưa kiểm tra")

    def test_kev_forces_p1(self):
        d = tempfile.mkdtemp()
        kev = os.path.join(d, "kev.json")
        with open(kev, "w") as fh:
            json.dump({"vulnerabilities": [{"cveID": "CVE-2099-0091", "dateAdded": "2026-01-01"}]}, fh)
        f = finding(run([native([native_vuln("CVE-2099-0091", "a", "1.0.0", "1.0.1", sev="MEDIUM")])], extra=["--kev", kev]), "a")
        self.assertEqual(f["suggested_priority"], "P1")
        self.assertIn("CISA KEV", f["priority_basis"])

    def test_epss_raises_priority(self):
        d = tempfile.mkdtemp()
        ep = os.path.join(d, "epss.csv")
        with open(ep, "w") as fh:
            fh.write("#model_version:v2025\ncve,epss,percentile\nCVE-2099-0092,0.42,0.97\n")
        f = finding(run([native([native_vuln("CVE-2099-0092", "a", "1.0.0", "1.0.1")])], extra=["--epss", ep]), "a")
        self.assertEqual(f["suggested_priority"], "P1")

    def test_uzomuzo_review_does_not_block_cve(self):
        f = finding(run([native([native_vuln("CVE-2099-0093", "a", "1.0.0", "1.0.1", sev="CRITICAL")])],
                        uzomuzo={"packages": [uz_pkg("pkg:npm/a@1.0.0", verdict="review", error="lookup failed")]}), "a")
        self.assertEqual((f["suggested_priority"], f["decision"]), ("P1", "Cần xử lý"))
        self.assertTrue(any("Uzomuzo review" in x for x in f["verify"]))

    def test_review_only_needs_verification(self):
        f = finding(run(uzomuzo={"packages": [uz_pkg("pkg:npm/b@1.0.0", verdict="review", error="not found")]}), "b")
        self.assertEqual((f["suggested_priority"], f["decision"]), ("P4", "Cần xác minh"))


class TestLifecycle(unittest.TestCase):
    def test_stalled_caution_is_limited_not_dead(self):
        f = finding(run(uzomuzo={"packages": [uz_pkg("pkg:npm/m@1.0.0", verdict="caution", lifecycle="Stalled")]}), "m")
        self.assertEqual(f["eol_status"], "Bảo trì hạn chế")
        self.assertEqual(f["suggested_priority"], "P3")

    def test_archived_is_unmaintained(self):
        f = finding(run(uzomuzo={"packages": [uz_pkg("pkg:npm/r@2.0.0", verdict="replace", lifecycle="Stalled", archived=True)]}), "r")
        self.assertEqual((f["eol_status"], f["section"], f["suggested_priority"]), ("Ngừng bảo trì", "EOL", "P2"))

    def test_version_branch_eol_from_endoflife(self):
        def http(url, data=None, timeout=20):
            if "endoflife.date/api/vue" in url:
                return [{"cycle": "3", "eol": False, "latest": "3.5.0"}, {"cycle": "2", "eol": "2023-12-31", "latest": "2.7.16"}]
            raise OSError("blocked")
        doc = sbom([spdx_pkg("A", "app", purpose="APPLICATION"), spdx_pkg("V", "vue", "2.7.16", "pkg:npm/vue@2.7.16")], [rel("A", "V", "DEPENDS_ON")])
        r = run(sbom_doc=doc, uzomuzo={"packages": [uz_pkg("pkg:npm/vue@2.7.16")]}, extra=["--online"], http_fn=http)
        f = finding(r, "vue")
        self.assertEqual((f["eol_status"], f["section"], f["suggested_priority"]), ("Nhánh hết hỗ trợ", "EOL", "P2"))
        self.assertEqual(f["eol_info"]["newest_supported_cycle"], "3")
        self.assertIn("lỗi", r["meta"]["coverage"]["fetch_status"]["kev"])  # KEV bị chặn → ghi nhận, không crash

    def test_trivy_eosl_os(self):
        t = native([], target="img (debian 10.13)", cls="os-pkgs", Metadata={"OS": {"Family": "debian", "Name": "10.13", "EOSL": True}})
        r = run([t])
        self.assertTrue(r["meta"]["platform_eol"][0]["is_eol"])


class TestCoverage(unittest.TestCase):
    def test_sbom_only_does_not_claim_clean(self):
        doc = sbom([spdx_pkg("A", "app", purpose="APPLICATION"), spdx_pkg("L", "a", "1.0.0", "pkg:npm/a@1.0.0")], [rel("A", "L", "DEPENDS_ON")])
        r = run(sbom_doc=doc)
        self.assertIsNone(r["stats"]["no_findings"])
        w = " ".join(r["meta"]["coverage"]["warnings"])
        self.assertIn("Không có dữ liệu lỗ hổng", w)
        self.assertIn("Không có Uzomuzo", w)

    def test_artifact_mismatch_warned(self):
        doc = sbom([spdx_pkg("C", "registry.example.com/team/app:1.0", purpose="CONTAINER")], [])
        r = run([[cq_issue("CVE-2099-0200", "libz", "1.0", sev="minor", path="registry.example.com/team/other:2.0 (debian 12.5)")]], sbom_doc=doc)
        self.assertEqual(r["meta"]["coverage"]["source_match"], "không khớp")

    def test_artifact_match(self):
        doc = sbom([spdx_pkg("C", "registry.example.com/team/app:1.0", purpose="CONTAINER")], [])
        r = run([[cq_issue("CVE-2099-0201", "libz", "1.0", sev="minor", path="registry.example.com/team/app:1.0 (debian 12.5)")]], sbom_doc=doc)
        self.assertEqual(r["meta"]["coverage"]["source_match"], "khớp")

    def test_codequality_without_fixed_version_warned(self):
        r = run([[cq_issue("CVE-2099-0202", "a", "1.0.0")]])
        self.assertTrue(any("code-quality" in w for w in r["meta"]["coverage"]["warnings"]))

    def test_old_scan_warned(self):
        doc = sbom([spdx_pkg("A", "app", purpose="APPLICATION")], [])
        r = run(sbom_doc=doc, today="2027-03-01")
        self.assertTrue(any("ngày" in w for w in r["meta"]["coverage"]["warnings"]))


if __name__ == "__main__":
    unittest.main()
