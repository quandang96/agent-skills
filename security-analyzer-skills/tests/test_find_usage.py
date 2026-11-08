import contextlib
import io
import json
import os
import tempfile
import unittest

from helpers import find_usage, native, native_vuln, rel, run, sbom, spdx_pkg


def write(root, rel_path, text):
    p = os.path.join(root, rel_path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(text)


class TestFindUsage(unittest.TestCase):
    def setUp(self):
        pk = [spdx_pkg("A", "app", purpose="APPLICATION"), spdx_pkg("E", "express", "4.17.1", "pkg:npm/express@4.17.1"),
              spdx_pkg("Q", "qs", "6.7.0", "pkg:npm/qs@6.7.0"), spdx_pkg("L", "lodash", "4.17.15", "pkg:npm/lodash@4.17.15"),
              spdx_pkg("P", "@nuxtjs/i18n", "7.0.0", "pkg:npm/%40nuxtjs/i18n@7.0.0"), spdx_pkg("U", "unused", "1.0.0", "pkg:npm/unused@1.0.0"),
              spdx_pkg("G", "github.com/gin-gonic/gin", "v1.9.0", "pkg:golang/github.com/gin-gonic/gin@v1.9.0")]
        rs = [rel("A", "E", "DEPENDS_ON"), rel("E", "Q", "DEPENDS_ON"), rel("A", "L", "DEPENDS_ON"), rel("A", "P", "DEPENDS_ON"),
              rel("A", "U", "DEPENDS_ON"), rel("A", "G", "DEPENDS_ON")]
        vs = [native_vuln("CVE-2099-1", "qs", "6.7.0", "6.7.3"), native_vuln("CVE-2099-2", "lodash", "4.17.15", "4.17.21"),
              native_vuln("CVE-2099-3", "@nuxtjs/i18n", "7.0.0", "7.0.1", purl="pkg:npm/%40nuxtjs/i18n@7.0.0"),
              native_vuln("CVE-2099-4", "unused", "1.0.0", "1.0.1"),
              native_vuln("CVE-2099-5", "github.com/gin-gonic/gin", "v1.9.0", "v1.9.1", eco="golang")]
        _, self.analysis = run([native(vs)], sbom_doc=sbom(pk, rs), keep_dir=True)
        self.src = tempfile.mkdtemp()
        write(self.src, "server/app.ts", "import express from 'express'\n")
        write(self.src, "report/render.js", "const t = require('lodash/template')\n")
        write(self.src, "nuxt.config.ts", "export default { modules: ['@nuxtjs/i18n'] }\n")
        write(self.src, "plugins/loader.js", "const m = require(pluginName)\n")
        write(self.src, "node_modules/unused/index.js", "require('unused')\n")
        write(self.src, "cmd/main.go", 'import "github.com/gin-gonic/gin"\n')
        self.gv = os.path.join(self.src, "govuln.json")
        with open(self.gv, "w") as fh:
            fh.write(
                '{"osv": {"id": "GO-2099-0001", "aliases": ["CVE-2099-5"]}}\n'
                '{"finding": {"osv": "GO-2099-0001", "trace": [{"module": "github.com/gin-gonic/gin", "package": "github.com/gin-gonic/gin",'
                ' "function": "Context.FileAttachment"}, {"module": "app", "function": "main"}]}}\n')
        with contextlib.redirect_stdout(io.StringIO()):
            find_usage.main([self.analysis, "--src", self.src, "--govulncheck", self.gv])
        with open(self.analysis) as fh:
            self.data = json.load(fh)

    def u(self, name):
        return next(f for f in self.data["findings"] if f["name"] == name)["usage"]

    def test_direct_import(self):
        u = self.u("lodash")
        self.assertEqual((u["level"], u["files"]), ("Import", 1))

    def test_transitive_via_parent(self):
        u = self.u("qs")
        self.assertEqual((u["level"], u["searched"], u["via_parent"]), ("Import", "express", True))
        self.assertTrue(any("Transitive" in x for x in u["limits"]))

    def test_config_plugin(self):
        u = self.u("@nuxtjs/i18n")
        self.assertEqual(u["level"], "Import")
        self.assertTrue(u["config_only"])

    def test_not_found_is_not_proof(self):
        u = self.u("unused")  # chỉ có trong node_modules → không tính
        self.assertEqual(u["level"], "Dependency")
        self.assertTrue(any("không chứng minh" in x for x in u["limits"]))
        self.assertTrue(any("dynamic import" in x for x in u["limits"]))

    def test_govulncheck_reachable(self):
        u = self.u("github.com/gin-gonic/gin")
        self.assertEqual(u["level"], "Reachable")
        self.assertIn("github.com/gin-gonic/gin.Context.FileAttachment", u["reachable_symbols"])

    def test_coverage_flag(self):
        self.assertTrue(self.data["meta"]["coverage"]["sources"]["source_code"])


if __name__ == "__main__":
    unittest.main()
