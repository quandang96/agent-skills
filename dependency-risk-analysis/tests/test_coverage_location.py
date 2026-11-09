"""Kiểm thử: độ phủ theo package, project gốc, vị trí cài đặt, cách đếm, định danh artifact."""
import contextlib
import io
import json
import os
import tempfile
import unittest

from helpers import find_usage, finding, native, native_vuln, rel, run, sbom, spdx_pkg

import find_usage as F


def cq(vid, name, ver, path="Node.js", sev="major"):
    return {"type": "issue", "check_name": "container_scanning", "description": f"{vid} - {name} - {ver} - t",
            "fingerprint": vid + name, "content": "x", "severity": sev, "location": {"path": path, "lines": {"begin": 0}}}


def libs_sbom(n=5, ver="2.0.0"):
    pk = [spdx_pkg("A", "app/package-lock.json", purpose="APPLICATION")] + \
         [spdx_pkg(f"L{i}", f"lib{i}", ver, f"pkg:npm/lib{i}@{ver}") for i in range(n)]
    return sbom(pk, [rel("A", f"L{i}", "CONTAINS") for i in range(n)])


class TestNoFindingsCoverage(unittest.TestCase):
    def test_null_when_uzomuzo_covers_nothing(self):
        uz = {"packages": [{"purl": f"pkg:pypi/other{i}@1.0", "verdict": "ok"} for i in range(5)]}
        r = run([native([])], uzomuzo=uz, sbom_doc=libs_sbom())
        self.assertIsNone(r["stats"]["no_findings"])
        self.assertEqual(r["meta"]["coverage"]["packages"]["lifecycle_covered"], 0)
        self.assertTrue(any("0/5" in w for w in r["meta"]["coverage"]["warnings"]))

    def test_counts_only_fully_covered(self):
        uz = {"packages": [{"purl": f"pkg:npm/lib{i}@2.0.0", "verdict": "ok"} for i in range(2)]}
        r = run([native([])], uzomuzo=uz, sbom_doc=libs_sbom())
        self.assertEqual(r["stats"]["no_findings"], 2)
        self.assertEqual(r["meta"]["coverage"]["packages"]["fully_covered"], 2)

    def test_no_trivy_means_null(self):
        uz = {"packages": [{"purl": f"pkg:npm/lib{i}@2.0.0", "verdict": "ok"} for i in range(5)]}
        self.assertIsNone(run(uzomuzo=uz, sbom_doc=libs_sbom())["stats"]["no_findings"])

    def test_uzomuzo_version_mismatch_matched_by_name(self):
        uz = {"packages": [{"purl": "pkg:npm/lib0@1.0.0", "verdict": "replace", "archived": True, "relation": "direct"}]}
        r = run([native([])], uzomuzo=uz, sbom_doc=libs_sbom())
        f = finding(r, "lib0")
        self.assertEqual((f["version"], f["uzomuzo_version"], f["eol_status"]), ("2.0.0", "1.0.0", "Ngừng bảo trì"))
        self.assertTrue(any("version khác" in w for w in r["meta"]["coverage"]["warnings"]))

    def test_uzomuzo_package_absent_from_image_needs_verification(self):
        uz = {"packages": [{"purl": "pkg:npm/devonly@1.0.0", "verdict": "replace", "archived": True}]}
        f = finding(run([native([])], uzomuzo=uz, sbom_doc=libs_sbom()), "devonly")
        self.assertEqual(f["decision"], "Cần xác minh")


class TestProjectRoot(unittest.TestCase):
    def _proj(self, pj):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "package.json"), "w") as fh:
            json.dump(pj, fh)
        return d

    def test_root_from_package_json_excluded(self):
        d = self._proj({"name": "OmniPlatform", "private": True})
        uz = {"packages": [{"purl": "pkg:npm/omniplatform@1.0.0", "verdict": "caution", "lifecycle": "Stalled", "relation": "direct"}]}
        r = run([native([])], uzomuzo=uz, extra=["--project", d])
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["meta"]["root_packages"][0]["source"], "package.json (private)")

    def test_root_from_trivy_relationship(self):
        t = native([], packages=[{"Name": "my-app", "Version": "1.0.0", "Identifier": {"PURL": "pkg:npm/my-app@1.0.0"}, "Relationship": "root"}])
        r = run([t], uzomuzo={"packages": [{"purl": "pkg:npm/my-app@1.0.0", "verdict": "review", "error": "not found"}]})
        self.assertEqual(r["findings"], [])

    def test_sbom_root_children_become_direct(self):
        pk = [spdx_pkg("A", "app/package-lock.json", purpose="APPLICATION"), spdx_pkg("R", "my-app", "1.0.0", "pkg:npm/my-app@1.0.0"),
              spdx_pkg("X", "x", "1.0.0", "pkg:npm/x@1.0.0"), spdx_pkg("Y", "y", "1.0.0", "pkg:npm/y@1.0.0")]
        rs = [rel("A", "R", "CONTAINS"), rel("A", "X", "CONTAINS"), rel("A", "Y", "CONTAINS"),
              rel("R", "X", "DEPENDS_ON"), rel("X", "Y", "DEPENDS_ON")]
        r = run([native([native_vuln("CVE-2099-0301", "x", "1.0.0", "1.0.1"), native_vuln("CVE-2099-0302", "y", "1.0.0", "1.0.1")])],
                sbom_doc=sbom(pk, rs), extra=["--root-package", "my-app"])
        self.assertEqual((finding(r, "x")["relation"], finding(r, "x")["relation_basis"]), ("direct", "SBOM"))
        self.assertEqual(finding(r, "y")["relation"], "transitive")
        self.assertNotIn("my-app", [f["name"] for f in r["findings"]])


class TestInstallLocation(unittest.TestCase):
    def _sbom(self):
        pk = [spdx_pkg("A", "app/package-lock.json", purpose="APPLICATION"), spdx_pkg("N", "Node.js", purpose="APPLICATION"),
              spdx_pkg("U1", "undici", "5.28.3", "pkg:npm/undici@5.28.3", ann={"FilePath": "app/node_modules/undici/package.json"}),
              spdx_pkg("U2", "undici", "5.28.3", "pkg:npm/undici@5.28.3",
                       ann={"FilePath": "usr/local/lib/node_modules/npm/node_modules/undici/package.json"}),
              spdx_pkg("B", "brace-expansion", "2.0.1", "pkg:npm/brace-expansion@2.0.1",
                       ann={"FilePath": "usr/local/lib/node_modules/npm/node_modules/brace-expansion/package.json"})]
        return sbom(pk, [rel("A", "U1", "CONTAINS"), rel("N", "U2", "CONTAINS"), rel("N", "B", "CONTAINS")])

    def test_same_package_split_by_location(self):
        r = run([[cq("CVE-2099-0401", "undici", "5.28.3")]], sbom_doc=self._sbom())
        locs = sorted(f["install_location"] for f in r["findings"] if f["name"] == "undici")
        self.assertEqual(locs, ["app", "base-image tooling"])

    def test_base_image_tooling_remediation(self):
        r = run([[cq("CVE-2099-0402", "brace-expansion", "2.0.1")]], sbom_doc=self._sbom())
        f = finding(r, "brace-expansion")
        self.assertEqual((f["install_location"], f["scope_display"], f["owner_hint"]), ("base-image tooling", "base-image tooling", "Platform"))
        self.assertIn("KHÔNG tác động", f["remediation_hint"])
        self.assertIsNone(f["relation"])

    def test_native_pkgpath_assigns_vuln_to_location(self):
        v1 = native_vuln("CVE-2099-0403", "undici", "5.28.3", "5.28.4")
        v1["PkgPath"] = "usr/local/lib/node_modules/npm/node_modules/undici/package.json"
        r = run([native([v1], target="Node.js")], sbom_doc=self._sbom())
        by = {f["install_location"]: f for f in r["findings"] if f["name"] == "undici"}
        self.assertEqual(list(by), ["base-image tooling"], "CVE chỉ thuộc bản trong npm của base image")

    def test_classify(self):
        c = __import__("aggregate").classify_location
        self.assertEqual(c("usr/local/lib/node_modules/npm/node_modules/x/package.json"), "base-image tooling")
        self.assertEqual(c("usr/local/lib/node_modules/pm2/package.json"), "image (global)")
        self.assertEqual(c("usr/local/bin/gosu"), "image binary")
        self.assertEqual(c("app/package-lock.json"), "app")
        self.assertIsNone(c("Node.js"))


class TestCounting(unittest.TestCase):
    def test_records_vs_unique(self):
        def fake(name, version, eco):
            return [{"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2099-0501"], "affected": []}]
        recs = native([native_vuln("CVE-2099-0501", "a", "1.0.0"), native_vuln("GHSA-aaaa-bbbb-cccc", "a", "1.0.0")])
        r = run([recs], extra=["--osv"], osv_query_fn=fake)
        c = r["stats"]["counting"]
        self.assertEqual((c["scanner_records"], c["distinct_ids"], c["unique_vulnerabilities"]), (2, 2, 1))

    def test_unique_unknown_without_alias_check(self):
        c = run([[cq("CVE-2099-0502", "a", "1.0.0", path="app/package-lock.json")]])["stats"]["counting"]
        self.assertIsNone(c["unique_vulnerabilities"])

    def test_advisory_without_id_counted(self):
        c = run([[cq("NO-ID-HERE", "a", "1.0.0")]])["stats"]["counting"]
        self.assertEqual(c["advisories_without_id"], 1)


class TestArtifactIdentity(unittest.TestCase):
    def _docs(self, sb_digest="sha256:aaa", t_digest="sha256:aaa"):
        doc = sbom([spdx_pkg("C", "registry.example.com/team/app:1.0", f"{sb_digest}", f"pkg:oci/app@{sb_digest}", purpose="CONTAINER")], [])
        t = native([], ArtifactName="registry.example.com/team/app:1.0",
                   Metadata={"RepoDigests": [f"registry.example.com/team/app@{t_digest}"], "ImageID": "sha256:config"})
        return t, doc

    def test_all_match_verified(self):
        t, doc = self._docs()
        m = run([t], sbom_doc=doc, extra=["--deployed-digest", "sha256:aaa"])["meta"]
        self.assertEqual((m["artifact_identity"]["trivy_sbom_deployment"], m["report_status_suggested"]), ("khớp", "Verified"))

    def test_deployed_mismatch_preliminary(self):
        t, doc = self._docs()
        m = run([t], sbom_doc=doc, extra=["--deployed-digest", "sha256:bbb"])["meta"]
        self.assertEqual((m["artifact_identity"]["trivy_sbom_deployment"], m["report_status_suggested"]), ("không khớp", "Preliminary"))

    def test_image_id_not_confused_with_repo_digest(self):
        t, doc = self._docs()
        self.assertEqual(run([t], sbom_doc=doc)["meta"]["artifact_identity"]["trivy_vs_sbom"], "khớp")

    def test_unknown_deployment_preliminary(self):
        t, doc = self._docs()
        m = run([t], sbom_doc=doc)["meta"]
        self.assertEqual((m["artifact_identity"]["trivy_sbom_deployment"], m["report_status_suggested"]), ("chưa xác minh", "Preliminary"))


class TestConfigUsage(unittest.TestCase):
    def test_plugin_vs_plain_string(self):
        pat = lambda n: F.config_pattern("npm", n)
        self.assertFalse(F.config_hit("export default { keycloak: { realm: 'omniplatform' } }", pat("omniplatform")))
        self.assertFalse(F.config_hit("export default { runtimeConfig: { public: { appName: 'x' } } }", pat("x")))
        self.assertTrue(F.config_hit("export default { modules: ['@nuxtjs/i18n'] }", pat("@nuxtjs/i18n")))
        self.assertTrue(F.config_hit("export default { modules: [['@nuxtjs/i18n', { locales: ['vi'] }]] }", pat("@nuxtjs/i18n")))
        self.assertTrue(F.config_hit('{ "plugins": ["babel-plugin-x"] }', pat("babel-plugin-x")))
        self.assertTrue(F.config_hit("module.exports = { preset: 'ts-jest' }", pat("ts-jest")))

    def test_root_and_base_image_not_scanned(self):
        src = tempfile.mkdtemp()
        with open(os.path.join(src, "package.json"), "w") as fh:
            json.dump({"name": "omniplatform", "private": True}, fh)
        with open(os.path.join(src, "nuxt.config.ts"), "w") as fh:
            fh.write("export default { keycloak: { realm: 'omniplatform' }, modules: [] }\n")
        with open(os.path.join(src, "index.js"), "w") as fh:
            fh.write("import { fetch } from 'undici'\n")
        _, path = run([[cq("CVE-2099-0601", "omniplatform", "1.0.0", path="app/package-lock.json")]], keep_dir=True)
        with contextlib.redirect_stdout(io.StringIO()):
            find_usage.main([path, "--src", src])
        with open(path) as fh:
            u = json.load(fh)["findings"][0]["usage"]
        self.assertEqual(u["level"], "Project root")


if __name__ == "__main__":
    unittest.main()
