"""Kiểm thử an toàn: dữ liệu quét/source code là dữ liệu không tin cậy."""
import contextlib
import io
import json
import os
import tempfile
import time
import unittest

from helpers import aggregate, find_usage, native, native_vuln, run


class TestUntrustedInput(unittest.TestCase):
    def test_field_regex_no_redos(self):
        for payload in [("-" * 2000 + "\n") * 200, "!" * 400000, ("|" * 3000 + "\n") * 100, "Package" + " " * 300000]:
            t = time.time()
            aggregate._field(payload[:aggregate.MAX_CONTENT], r"Package(?:\s*Name)?", r"Installed\s*Version", r"Fixed\s*Version", "Status")
            aggregate._field(payload, r"Package(?:\s*Name)?")
            self.assertLess(time.time() - t, 0.5)

    def test_huge_content_is_truncated(self):
        issue = {"type": "issue", "check_name": "container_scanning", "description": "CVE-2099-9 - a - 1.0.0 - t",
                 "fingerprint": "x", "content": ("-" * 2000 + "\n") * 2000, "severity": "major",
                 "location": {"path": "p", "lines": {"begin": 0}}}
        t = time.time()
        run([[issue] * 50])
        self.assertLess(time.time() - t, 5)

    def test_secret_value_not_stored(self):
        t = native([])
        t["Results"][0]["Secrets"] = [{"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "Title": "AWS Access Key ID",
                                       "Match": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}]
        r = run([t])
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", json.dumps(r))

    def test_http_only_https(self):
        with self.assertRaises(ValueError):
            aggregate.http_json("http://example.com/x.json")


class TestPrivacy(unittest.TestCase):
    def test_private_packages_not_sent_to_osv(self):
        sent = []

        def fake(name, version, eco):
            sent.append(name)
            return []
        vs = [native_vuln("CVE-2099-10", "@acme/core", "1.0.0", purl="pkg:npm/%40acme/core@1.0.0"),
              native_vuln("CVE-2099-11", "internal-utils", "1.0.0"),
              native_vuln("CVE-2099-12", "lodash", "4.17.15")]
        uz = {"packages": [{"purl": "pkg:npm/internal-utils@1.0.0", "verdict": "review", "error": "package not found in registry"}]}
        r = run([native(vs)], uzomuzo=uz, extra=["--osv", "--private-pattern", "@acme/*"], osv_query_fn=fake)
        self.assertEqual(sent, ["lodash"])
        self.assertEqual(r["meta"]["coverage"]["sources"]["osv"]["skipped_private"], 2)


class TestSourceScan(unittest.TestCase):
    def test_symlinks_outside_repo_are_not_read(self):
        base = tempfile.mkdtemp()
        repo, outside = os.path.join(base, "repo"), os.path.join(base, "outside")
        os.makedirs(os.path.join(repo, "src"))
        os.makedirs(outside)
        with open(os.path.join(outside, "x.js"), "w") as fh:
            fh.write("require('lodash')")
        with open(os.path.join(repo, "src", "real.js"), "w") as fh:
            fh.write("// nothing")
        os.symlink(os.path.join(outside, "x.js"), os.path.join(repo, "src", "link.js"))
        os.symlink(outside, os.path.join(repo, "linkdir"))
        files = list(find_usage.walk([repo]))
        self.assertEqual([os.path.basename(f) for f in files], ["real.js"])

    def test_large_files_skipped(self):
        repo = tempfile.mkdtemp()
        with open(os.path.join(repo, "bundle.js"), "w") as fh:
            fh.write("x" * (find_usage.MAX_FILE + 1))
        self.assertEqual(list(find_usage.walk([repo])), [])


if __name__ == "__main__":
    unittest.main()
