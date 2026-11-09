import unittest

from helpers import SCRIPTS  # noqa: F401  (thêm scripts vào sys.path)
import versions as V


class TestCompare(unittest.TestCase):
    def check(self, eco, lo, hi):
        self.assertEqual(V.compare(lo, hi, eco), -1, f"{eco}: {lo} < {hi}")
        self.assertEqual(V.compare(hi, lo, eco), 1, f"{eco}: {hi} > {lo}")

    def test_debian(self):
        self.check("deb", "1:9.0-1", "2:1.0-1")            # epoch xét trước
        self.check("deb", "1.0~rc1-1", "1.0-1")            # ~ nhỏ hơn rỗng
        self.check("deb", "3.0.11-1~deb12u2", "3.0.14-1~deb12u2")
        self.check("deb", "3.0.14-1~deb12u1", "3.0.14-1~deb12u2")
        self.check("deb", "2.36-9+deb12u3", "2.36-9+deb12u10")
        self.assertEqual(V.compare("1.0-1", "0:1.0-1", "deb"), 0)

    def test_rpm(self):
        self.check("rpm", "1.0~rc1-1", "1.0-1")
        self.check("rpm", "1.1.1k-9.el8", "1.1.1k-12.el8")
        self.check("rpm", "1:1.0-1", "2:0.1-1")
        self.check("rpm", "1.0a", "1.0.1")

    def test_apk(self):
        self.check("apk", "3.1.4-r5", "3.1.4-r6")
        self.check("apk", "1.2.3_rc1-r0", "1.2.3-r0")
        self.check("apk", "1.2.3-r0", "1.2.3_p1-r0")

    def test_pep440(self):
        self.check("pypi", "1.0", "1.0.post1")
        self.check("pypi", "1.0rc1", "1.0")
        self.check("pypi", "1.0.dev1", "1.0a1")
        self.check("pypi", "1.9", "1.10")
        self.check("pypi", "1!0.1", "2!0.0")

    def test_pep440_fallback(self):
        self.assertEqual(V._cmp(V._pep_key("1.0"), V._pep_key("1.0.post1")), -1)
        self.assertEqual(V._cmp(V._pep_key("1.0.dev1"), V._pep_key("1.0a1")), -1)
        self.assertEqual(V._cmp(V._pep_key("1!0.1")[:1], V._pep_key("2!0.0")[:1]), -1)

    def test_maven(self):
        self.check("maven", "1.0-SNAPSHOT", "1.0")
        self.check("maven", "1.0-rc1", "1.0")
        self.check("maven", "1.0", "1.0-sp1")
        self.check("maven", "2.9.10", "2.9.10.1")
        self.assertEqual(V.compare("1.0", "1.0.0", "maven"), 0)

    def test_semver(self):
        self.check("npm", "1.0.0-rc.1", "1.0.0")
        self.check("npm", "1.0.0-alpha.2", "1.0.0-alpha.10")
        self.check("golang", "v0.0.0-20210101000000-abcdef", "v0.1.0")
        self.check("npm", "4.17.9", "4.17.21")


class TestFixes(unittest.TestCase):
    def test_branch_aware(self):
        fl = ["6.7.3", "6.8.3"]
        self.assertTrue(V.fixes("6.7.3", "6.7.0", fl, "npm"))
        self.assertFalse(V.fixes("6.8.1", "6.7.0", fl, "npm"), "nhánh 6.8 cần 6.8.3")
        self.assertTrue(V.fixes("6.8.3", "6.7.0", fl, "npm"))

    def test_no_fix_below_target(self):
        self.assertFalse(V.fixes("0.21.2", "0.21.1", ["1.6.0"], "npm"))
        self.assertTrue(V.fixes("1.6.0", "0.21.1", ["1.6.0"], "npm"))

    def test_osv_ranges(self):
        ranges = [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}, {"introduced": "2.0.0"}, {"fixed": "2.0.5"}]}]
        self.assertTrue(V.in_osv_ranges("2.0.1", ranges, "npm"))
        self.assertFalse(V.in_osv_ranges("1.5.0", ranges, "npm"))
        self.assertTrue(V.fixes("1.5.0", "1.0.0", [], "npm", ranges))
        self.assertFalse(V.fixes("2.0.1", "1.0.0", [], "npm", ranges))

    def test_debian_epoch_fix(self):
        self.assertTrue(V.fixes("1:2.0-1", "1:1.0-1", ["1:1.5-1"], "deb"))
        self.assertFalse(V.fixes("9.0-1", "1:1.0-1", ["1:1.5-1"], "deb"), "9.0-1 (epoch 0) < 1:1.5-1")


if __name__ == "__main__":
    unittest.main()
