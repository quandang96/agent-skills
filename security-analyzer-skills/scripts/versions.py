"""
So sánh version theo từng ecosystem và kiểm tra một version có vá CVE hay không.

compare(a, b, eco) -> -1 | 0 | 1
  eco = loại purl: deb, rpm, apk, pypi, maven, npm, golang, cargo, nuget, gem, composer, ...
  - deb   : thuật toán dpkg (epoch, upstream, revision, '~' < rỗng)
  - rpm   : rpmvercmp (epoch:version-release, hỗ trợ '~' và '^')
  - apk   : Alpine (suffix _alpha < _beta < _pre < _rc < (none) < _cvs < _svn < _git < _hg < _p, -rN)
  - pypi  : PEP 440 (dùng `packaging` nếu có, nếu không dùng bản cài sẵn bên dưới)
  - maven : xấp xỉ ComparableVersion (alpha < beta < milestone < rc < snapshot < release < sp)
  - semver: npm, golang, cargo, nuget, composer, hex, pub (prerelease < release)
  - khác  : so sánh token số/chữ (xấp xỉ)
"""
import re

SEMVER_ECOS = {"npm", "golang", "cargo", "nuget", "composer", "hex", "pub", "swift", "conan", "cocoapods"}


def _sign(x):
    return (x > 0) - (x < 0)


def _cmp(a, b):
    return (a > b) - (a < b)


# ------------------------------------------------------------------ Debian (dpkg)
def _deb_order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _deb_verrevcmp(a, b):
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = _deb_order(a[i]) if i < la else 0
            bc = _deb_order(b[j]) if j < lb else 0
            if ac != bc:
                return _sign(ac - bc)
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and a[i].isdigit() and j < lb and b[j].isdigit():
            if not first_diff:
                first_diff = _cmp(a[i], b[j])
            i += 1
            j += 1
        if i < la and a[i].isdigit():
            return 1
        if j < lb and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def deb_split(v):
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, rest = v.split(":", 1)
        if e.isdigit():
            epoch, v = int(e), rest
    up, rev = (v.rsplit("-", 1) if "-" in v else (v, ""))
    return epoch, up, rev


def deb_cmp(a, b):
    ea, ua, ra = deb_split(a)
    eb, ub, rb = deb_split(b)
    if ea != eb:
        return _cmp(ea, eb)
    return _deb_verrevcmp(ua, ub) or _deb_verrevcmp(ra, rb)


# ------------------------------------------------------------------ RPM
def _rpmvercmp(a, b):
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        while i < la and not a[i].isalnum() and a[i] not in "~^":
            i += 1
        while j < lb and not b[j].isalnum() and b[j] not in "~^":
            j += 1
        ta, tb = (i < la and a[i] == "~"), (j < lb and b[j] == "~")
        if ta or tb:
            if not ta:
                return 1
            if not tb:
                return -1
            i += 1
            j += 1
            continue
        ca, cb = (i < la and a[i] == "^"), (j < lb and b[j] == "^")
        if ca or cb:
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if not ca:
                return 1
            if not cb:
                return -1
            i += 1
            j += 1
            continue
        if not (i < la and j < lb):
            break
        si, sj = i, j
        isnum = a[i].isdigit()
        if isnum:
            while i < la and a[i].isdigit():
                i += 1
            while j < lb and b[j].isdigit():
                j += 1
        else:
            while i < la and a[i].isalpha():
                i += 1
            while j < lb and b[j].isalpha():
                j += 1
        sa, sb = a[si:i], b[sj:j]
        if not sb:
            return 1 if isnum else -1
        if isnum:
            sa, sb = sa.lstrip("0"), sb.lstrip("0")
            if len(sa) != len(sb):
                return _cmp(len(sa), len(sb))
        if sa != sb:
            return _cmp(sa, sb)
    if i >= la and j >= lb:
        return 0
    return -1 if i >= la else 1


def rpm_split(v):
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, rest = v.split(":", 1)
        if e.isdigit():
            epoch, v = int(e), rest
    ver, rel = (v.rsplit("-", 1) if "-" in v else (v, ""))
    return epoch, ver, rel


def rpm_cmp(a, b):
    ea, va, ra = rpm_split(a)
    eb, vb, rb = rpm_split(b)
    if ea != eb:
        return _cmp(ea, eb)
    r = _rpmvercmp(va, vb)
    if r or not (ra and rb):
        return r
    return _rpmvercmp(ra, rb)


# ------------------------------------------------------------------ Alpine apk
_APK_SUF = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}
_APK_RE = re.compile(r"^(\d+(?:\.\d+)*)([a-z]?)((?:_[a-z]+\d*)*)(?:~[0-9a-f]+)?(?:-r(\d+))?$")


def _apk_key(v):
    m = _APK_RE.match(v.strip())
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(".")]
    sufs = [(_APK_SUF.get(s, 0), int(n or 0)) for s, n in re.findall(r"_([a-z]+)(\d*)", m.group(3))]
    return nums, m.group(2), sufs, int(m.group(4) or 0)


def apk_cmp(a, b):
    ka, kb = _apk_key(a), _apk_key(b)
    if ka is None or kb is None:
        return generic_cmp(a, b)
    (na, la, sa, ra), (nb, lb, sb, rb) = ka, kb
    for k in range(max(len(na), len(nb))):
        x = na[k] if k < len(na) else -1
        y = nb[k] if k < len(nb) else -1
        if x != y:
            return _cmp(x, y)
    if la != lb:
        return _cmp(la, lb)
    for k in range(max(len(sa), len(sb))):
        x = sa[k] if k < len(sa) else (0, 0)
        y = sb[k] if k < len(sb) else (0, 0)
        if x != y:
            return _cmp(x, y)
    return _cmp(ra, rb)


# ------------------------------------------------------------------ PEP 440
_PEP_RE = re.compile(
    r"^\s*v?(?:(\d+)!)?(\d+(?:\.\d+)*)"
    r"(?:[-_.]?(a|alpha|b|beta|c|rc|pre|preview)[-_.]?(\d*))?"
    r"(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d*))?"
    r"(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+[a-z0-9.]+)?\s*$", re.I)
_NEG, _POS = (0,), (2,)


def _pep_key(v):
    m = _PEP_RE.match(v)
    if not m:
        return None
    epoch = int(m.group(1) or 0)
    rel = [int(x) for x in m.group(2).split(".")]
    while len(rel) > 1 and rel[-1] == 0:
        rel.pop()
    pre_l, pre_n = m.group(3), m.group(4)
    post_n = m.group(5) if m.group(5) is not None else (m.group(7) if m.group(6) else None)
    has_post = m.group(5) is not None or m.group(6) is not None
    dev = m.group(8)
    if pre_l:
        rank = {"a": 0, "alpha": 0, "b": 1, "beta": 1}.get(pre_l.lower(), 2)
        pre = (1, rank, int(pre_n or 0))
    elif not has_post and dev:
        pre = _NEG
    else:
        pre = _POS
    post = (1, int(post_n or 0)) if has_post else _NEG
    devk = (1, int(m.group(9) or 0)) if dev else _POS
    return epoch, rel, pre, post, devk


def pep440_cmp(a, b):
    try:
        from packaging.version import Version
        return _cmp(Version(a), Version(b))
    except Exception:
        pass
    ka, kb = _pep_key(a), _pep_key(b)
    if ka is None or kb is None:
        return generic_cmp(a, b)
    (ea, ra, *rest_a), (eb, rb, *rest_b) = ka, kb
    if ea != eb:
        return _cmp(ea, eb)
    for k in range(max(len(ra), len(rb))):
        x = ra[k] if k < len(ra) else 0
        y = rb[k] if k < len(rb) else 0
        if x != y:
            return _cmp(x, y)
    return _cmp(tuple(rest_a), tuple(rest_b))


# ------------------------------------------------------------------ Maven
_MVN_Q = {"alpha": 0, "a": 0, "beta": 1, "b": 1, "milestone": 2, "m": 2, "rc": 3, "cr": 3,
          "snapshot": 4, "": 5, "ga": 5, "final": 5, "release": 5, "sp": 6}


def _mvn_items(v):
    items = []
    for t in re.findall(r"\d+|[a-zA-Z]+", v.lower()):
        if t.isdigit():
            items.append((1, int(t), ""))
        else:
            q = _MVN_Q.get(t)
            items.append((0, 7, t) if q is None else (0, q, ""))
    while items and (items[-1] == (1, 0, "") or items[-1][:2] == (0, 5)):
        items.pop()
    return items


def _mvn_vs_null(x):
    if x[0] == 1:
        return 1 if x[1] > 0 else 0
    return _cmp(x[1], 5)


def maven_cmp(a, b):
    ia, ib = _mvn_items(a), _mvn_items(b)
    for k in range(max(len(ia), len(ib))):
        x = ia[k] if k < len(ia) else None
        y = ib[k] if k < len(ib) else None
        if x == y:
            continue
        if x is None or y is None:
            r = -_mvn_vs_null(y) if x is None else _mvn_vs_null(x)
            if r:
                return r
            continue
        if x[0] != y[0]:
            return 1 if x[0] == 1 else -1
        return _cmp(x[1:], y[1:])
    return 0


# ------------------------------------------------------------------ SemVer
_SEMVER_RE = re.compile(r"^\s*[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\s*$")


def semver_cmp(a, b):
    ma, mb = _SEMVER_RE.match(a or ""), _SEMVER_RE.match(b or "")
    if not ma or not mb:
        return None
    na = [int(x or 0) for x in ma.groups()[:4]]
    nb = [int(x or 0) for x in mb.groups()[:4]]
    if na != nb:
        return _cmp(na, nb)
    pa, pb = ma.group(5), mb.group(5)
    if pa == pb:
        return 0
    if pa is None:
        return 1
    if pb is None:
        return -1
    xa, xb = pa.split("."), pb.split(".")
    for x, y in zip(xa, xb):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return _cmp(int(x), int(y))
        if x.isdigit():
            return -1
        if y.isdigit():
            return 1
        return _cmp(x, y)
    return _cmp(len(xa), len(xb))


# ------------------------------------------------------------------ fallback
def _tokens(v):
    v = (v or "").strip().lstrip("vV")
    return [int(t) if t.isdigit() else t for t in re.findall(r"\d+|[a-zA-Z]+", v)]


def generic_cmp(a, b):
    ta, tb = _tokens(a), _tokens(b)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return _cmp(x, y)
        if isinstance(x, int):
            return 1
        if isinstance(y, int):
            return -1
        return _cmp(x, y)
    if len(ta) == len(tb):
        return 0
    longer, sign = (ta, 1) if len(ta) > len(tb) else (tb, -1)
    nxt = longer[min(len(ta), len(tb))]
    return sign if isinstance(nxt, int) else -sign


# ------------------------------------------------------------------ public API
def compare(a, b, eco=None):
    eco = (eco or "").lower()
    if a == b:
        return 0
    try:
        if eco == "deb":
            return deb_cmp(a, b)
        if eco == "rpm":
            return rpm_cmp(a, b)
        if eco == "apk":
            return apk_cmp(a, b)
        if eco == "pypi":
            return pep440_cmp(a, b)
        if eco == "maven":
            return maven_cmp(a, b)
        if eco in SEMVER_ECOS:
            r = semver_cmp(a, b)
            if r is not None:
                return r
    except Exception:
        pass
    return generic_cmp(a, b)


def sort_versions(vs, eco=None):
    import functools
    return sorted(set(vs), key=functools.cmp_to_key(lambda x, y: compare(x, y, eco)))


def branch(v, eco=None, depth=2):
    """(major, minor) dùng để nhận diện nhánh vá. Debian/RPM: lấy phần upstream, bỏ epoch."""
    v = v or ""
    if eco == "deb":
        v = deb_split(v)[1]
    elif eco == "rpm":
        v = rpm_split(v)[1]
    nums = [int(t) for t in re.findall(r"\d+", v.split("+")[0])]
    return tuple((nums + [0] * depth)[:depth])


def in_osv_ranges(v, ranges, eco=None):
    """True nếu v nằm trong khoảng bị ảnh hưởng của OSV (type SEMVER/ECOSYSTEM)."""
    for rg in ranges or []:
        if rg.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        start = None
        for e in rg.get("events", []):
            if "introduced" in e:
                start = e["introduced"]
            elif "fixed" in e and start is not None:
                if (start == "0" or compare(v, start, eco) >= 0) and compare(v, e["fixed"], eco) < 0:
                    return True
                start = None
            elif "last_affected" in e and start is not None:
                if (start == "0" or compare(v, start, eco) >= 0) and compare(v, e["last_affected"], eco) <= 0:
                    return True
                start = None
            elif "limit" in e:
                pass
        if start is not None and (start == "0" or compare(v, start, eco) >= 0):
            return True
    return False


def fixes(target, installed, fixed_list, eco=None, osv_ranges=None):
    """True nếu `target` đã vá CVE.
    - Có OSV ranges: kiểm tra chính xác target không nằm trong khoảng bị ảnh hưởng.
    - Chỉ có danh sách fixed version (Trivy): target >= một bản fix (> installed) VÀ nhánh của target
      không còn bản fix nào lớn hơn target (vd fixed = [6.7.3, 6.8.3]: 6.8.1 vẫn dính).
    """
    if not target:
        return False
    if osv_ranges:
        return not in_osv_ranges(target, osv_ranges, eco)
    if not fixed_list:
        return False
    ok = [f for f in fixed_list if compare(f, target, eco) <= 0 and (not installed or compare(f, installed, eco) > 0)]
    if not ok:
        return False
    br = branch(target, eco)
    return not any(branch(f, eco) == br and compare(f, target, eco) > 0 for f in fixed_list)
