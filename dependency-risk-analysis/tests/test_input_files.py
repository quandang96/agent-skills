"""Kiểm thử: nguồn phát hiện (file input + vị trí) và số liệu quét theo từng file input."""
import unittest

from helpers import finding, native, native_vuln, rel, run, sbom, spdx_pkg


def cq(vid, name, ver, path="app/package-lock.json", sev="major"):
    return {"type": "issue", "check_name": "container_scanning", "description": f"{vid} - {name} - {ver} - t",
            "fingerprint": vid + name, "content": "x", "severity": sev, "location": {"path": path, "lines": {"begin": 0}}}


class TestFoundIn(unittest.TestCase):
    def setUp(self):
        pk = [spdx_pkg("C", "registry.example.com/team/app:1.0", purpose="CONTAINER"),
              spdx_pkg("A", "app/package-lock.json", purpose="APPLICATION"),
              spdx_pkg("L", "lodash", "4.17.15", "pkg:npm/lodash@4.17.15"),
              spdx_pkg("R", "request", "2.88.2", "pkg:npm/request@2.88.2")]
        doc = sbom(pk, [rel("C", "A", "CONTAINS"), rel("A", "L", "DEPENDS_ON"), rel("A", "R", "DEPENDS_ON")])
        uz = {"packages": [{"purl": "pkg:npm/request@2.88.2", "verdict": "replace", "archived": True, "relation": "direct"},
                           {"purl": "pkg:npm/lodash@4.17.15", "verdict": "ok", "relation": "direct"}]}
        self.r = run([[cq("CVE-2099-0701", "lodash", "4.17.15"), cq("CVE-2099-0702", "lodash", "4.17.15")],
                      native([native_vuln("CVE-2099-0701", "lodash", "4.17.15", "4.17.21")])],
                     uzomuzo=uz, sbom_doc=doc)

    def files(self, name):
        return {x["file"]: x["locations"] for x in finding(self.r, name)["found_in"]}

    def test_cve_found_in_trivy_and_sbom(self):
        fi = self.files("lodash")
        self.assertEqual(fi["trivy0.json"], ["app/package-lock.json"])
        self.assertIn("trivy1.json", fi)
        self.assertIn("sbom.json", fi)

    def test_per_cve_sources(self):
        v = {x["id"]: x["sources"] for x in finding(self.r, "lodash")["vulns"]}
        self.assertEqual(sorted(v["CVE-2099-0701"]), ["trivy0.json", "trivy1.json"])
        self.assertEqual(v["CVE-2099-0702"], ["trivy0.json"])

    def test_eol_found_in_uzomuzo(self):
        fi = self.files("request")
        self.assertEqual(fi["uzomuzo.json"], ["packages[] pkg:npm/request@2.88.2"])

    def test_input_file_stats(self):
        by = {x["file"]: x for x in self.r["meta"]["input_files"]}
        self.assertEqual((by["trivy0.json"]["kind"], by["trivy0.json"]["records"], by["trivy0.json"]["with_fixed_version"]),
                         ("Trivy code-quality", 2, 0))
        self.assertEqual((by["trivy1.json"]["kind"], by["trivy1.json"]["with_fixed_version"]), ("Trivy JSON gốc", 1))
        self.assertEqual(by["uzomuzo.json"]["by_verdict"], {"replace": 1, "ok": 1})
        self.assertEqual(by["uzomuzo.json"]["sbom_match"]["exact"], 2)
        self.assertEqual((by["sbom.json"]["app_packages"], by["sbom.json"]["dependency_edges"]), (2, 2))
        self.assertEqual(by["trivy0.json"]["flagged"], 1)
        self.assertEqual(by["uzomuzo.json"]["flagged"], 2)

    def test_container_name_not_project_root(self):
        r = run([native([])], sbom_doc=sbom([spdx_pkg("C", "app", "sha256:1", "pkg:oci/app@sha256:1", purpose="CONTAINER")], []),
                extra=["--root-package", "app"])
        sb = next(x for x in r["meta"]["input_files"] if x["file"] == "sbom.json")
        self.assertEqual(sb["project_roots_excluded"], 0)


if __name__ == "__main__":
    unittest.main()
