# Template báo cáo phân tích dependency

> **Cách dùng:** Giữ đúng thứ tự và tên các mục. Thay toàn bộ placeholder `<...>` bằng dữ liệu đã xác minh. Bỏ dòng hoặc mục không có dữ liệu thay vì để trống. Không đưa dữ liệu mẫu hoặc dữ liệu của một báo cáo khác vào template.
>
> **Nguyên tắc:** Chỉ ghi kết luận được nguồn dữ liệu hỗ trợ. Không suy ra trạng thái của image từ `package.json`, lockfile hoặc Dockerfile. Không gọi số record của scanner là số vulnerability duy nhất trước khi chuẩn hóa alias CVE/GHSA/OSV.
>
> **Cấu trúc:** 1. Tổng quan (số liệu theo file input + kết luận) → 2. Danh sách lỗi (mỗi nhóm lỗi một hàng) → 3. Phân tích chi tiết CVE / EOL (sắp từ ưu tiên cao xuống thấp) → 4. Cần xác minh.
>
> **Mã tham chiếu:** mỗi hàng ở mục 2 có mã `C<n>` (CVE), `E<n>` (EOL) hoặc `V<n>` (chỉ cần xác minh / theo dõi). Thẻ chi tiết ở mục 3 dùng đúng mã đó để người đọc tra qua lại.

---

# Báo cáo phân tích thư viện - `<artifact/project>`

`<ngày báo cáo>` · **Trạng thái báo cáo:** `<Preliminary | Verified | Closed>`

## 1. Tổng quan

### 1.1. Kết quả quét theo file input

| File input | Loại | Số liệu quét | Phát hiện chính | Đóng góp vào danh sách lỗi | Giới hạn |
|---|---|---|---|:-:|---|
| `<trivy.json>` | `<Trivy code-quality / Trivy JSON gốc>` | `<n>` record · `<n>` ID · `<n>` package | CRITICAL `<n>` · HIGH `<n>` · MEDIUM `<n>` · LOW `<n>` · issue khác: `<secret n, misconfig n>` | `<n>` | `<vd: không có fixed version/status>` |
| `<uzomuzo-report.json>` | Uzomuzo | `<n>` package | ok `<n>` · caution `<n>` · replace `<n>` · review `<n>` | `<n>` | Khớp SBOM: `<exact>` đúng version · `<by_name>` lệch version · `<not_in_sbom>` không có trong image · `<root>` project gốc đã loại |
| `<sbom>.json` | `<SBOM SPDX-x.y>` | `<n>` package (app `<n>`, OS `<n>`) · `<n>` dependency edge | Artifact `<image:tag>` · digest `<sha256:… | không có>` · tạo `<timestamp>` | `<n>` | `<vd: không có dependency graph>` |
| `<kev.json / epss.csv>` | `<CISA KEV / EPSS>` | `<n>` CVE | `<n>` CVE trong báo cáo nằm trong KEV / EPSS ≥ 0.1 | - | - |
| Source code `<repo>` | Mã nguồn (chỉ tìm nơi sử dụng) | `<n>` file đã quét | `<n>` thư viện có bằng chứng [Import] · `<n>` [Reachable] | - | `<dynamic import n file>` |

> Mỗi file một hàng. Không có file nào thì ghi hàng đó với `✗ không có dữ liệu` ở cột Số liệu quét và nêu ảnh hưởng ở cột Giới hạn.

### 1.2. Kết luận tổng quan

| Hạng mục | Kết quả |
|---|---|
| **Trạng thái báo cáo** | `<Preliminary | Verified>` - `<lý do, vd digest deployment chưa xác minh>` |
| **Artifact** | `<registry/image:tag>` · Trivy ↔ SBOM: `<khớp | không khớp | chưa xác minh>` (`<digest | tên image>`) · ↔ deployment: `<khớp | không khớp | chưa xác minh>` · env `<…>` · revision `<…>` |
| **Thời điểm quét** | Trivy `<timestamp | chưa xác định>` · SBOM `<timestamp>` |
| **Số lượng lỗi** | `<n>` record · `<n>` ID · `<n | chưa xác định>` vulnerability duy nhất (sau chuẩn hóa alias) · `<n>` package bị ảnh hưởng · `<n>` advisory thiếu ID |
| **Theo ưu tiên** | 🔴 P1: `<n>` · 🟠 P2: `<n>` · 🟡 P3: `<n>` · ⚪ P4: `<n>` |
| **Theo quyết định** | Cần xử lý `<n>` · Cần xác minh `<n>` · Theo dõi `<n>` · Không áp dụng (vendor) `<n>` CVE |
| **Theo nhóm** | CVE `<n>` · EOL `<n>` · nằm ở base image / công cụ toàn cục `<n>` |
| **Không phát hiện vấn đề** | `<n>/<m> package có đủ dữ liệu lỗ hổng + vòng đời | không kết luận (thiếu nguồn)>` |
| **Độ phủ dữ liệu** | Trivy `<✓/✗>` · Trivy JSON gốc `<✓/✗>` · Uzomuzo `<✓/✗>` · SBOM `<✓/✗>` · KEV `<✓/✗>` · EPSS `<✓/✗>` · Source code `<✓/✗>` · Reachability `<✓/✗>` |
| **Cảnh báo chính** | ⚠ `<cảnh báo 1 làm thay đổi kết luận>`<br>⚠ `<cảnh báo 2>`<br>⚠ `<cảnh báo 3>` |
| **Việc cần làm ngay** | `<1-2 câu: hành động quyết định tiếp theo; ưu tiên xác minh digest/applicability hoặc remediation P1-P2. Không tự đặt SLA.>` |

> Tối đa ba cảnh báo. Thiếu KEV/EPSS → nêu một lần ở đây rằng priority là tạm thời. Digest chưa khớp hoặc chưa biết → trạng thái `Preliminary`.

---

## 2. Danh sách lỗi

| # | Lỗi | Package / nhóm | Phát hiện ở (file · vị trí) | Hiện tại | Cần nâng lên | Loại | Mức độ | Ưu tiên | Phạm vi | Quyết định | Rủi ro nâng cấp |
|:-:|---|---|---|---|---|:-:|---|:-:|---|---|:-:|
| C1 | `<CVE-ID>` `<tên ngắn>` · `+N` | `<package hoặc nhóm OS>` | `<trivy.json>`: `<target/path>`<br>`<sbom.json>`: `<vị trí cài đặt>` | `<version>` | `<minimum fixed version | ? >` `<(vá x/y)>` | CVE | `<CRITICAL (n CVE)>` | 🔴 P1 | `<runtime | dev | test | build | optional | base-image tooling | image (global) | image binary | không rõ>` | Cần xử lý | `<Thấp | Trung bình | Cao | Chưa xác minh>` |
| E1 | `<Ngừng bảo trì | Nhánh hết hỗ trợ | Bảo trì hạn chế>` `<(archived / replace / EOL ngày…)>` | `<package>` | `<uzomuzo-report.json>`: `<packages[] purl>`<br>`<sbom.json>`: `<vị trí>` | `<version>` | `<thay thế bằng … | nhánh … | ?>` | EOL | `<trạng thái + CVE kèm theo>` | 🟠 P2 | `<…>` | Cần xử lý | `<…>` |
| V1 | `<lý do cần xác minh / theo dõi>` | `<package>` | `<file · vị trí>` | `<version>` | `?` | `<CVE | EOL | Metadata>` | `<…>` | ⚪ P4 `<(tạm)>` | `<…>` | `<Cần xác minh | Theo dõi>` | - |

**Quy tắc cho bảng:**

- Mọi finding P1-P4 phải có trong bảng; không ẩn P1-P2. Sắp theo ưu tiên (P1 → P4), sau đó theo severity / mức độ lifecycle.
- Mã: `C` nếu `section = CVE`, `E` nếu `section = EOL`, `V` nếu chỉ cần xác minh / theo dõi. Đánh số tăng dần theo thứ tự trong bảng.
- Mỗi nhóm lỗi một hàng: một package (nhiều CVE gom chung, cột Lỗi ghi tối đa 2 ID rồi `+N`), hoặc một nhóm gói OS cùng source package. Cùng package ở 2 vị trí (app và base image) là 2 hàng.
- **Phát hiện ở:** liệt kê file input đã báo lỗi (`found_in`) kèm vị trí trong file đó (target/đường dẫn của Trivy, `packages[] purl` của Uzomuzo, vị trí cài đặt trong SBOM). Tối đa 3 dòng, ngăn bằng `<br>`.
- **Cần nâng lên:** dùng **minimum fixed version** từ Trivy / OSV / GHSA / advisory / distro tracker. Không dùng `stable_version` của Uzomuzo. Vá một phần ghi `(vá x/y)`; chưa xác định ghi `?`.
- `not_affected` không vào bảng (chỉ đếm ở 1.2). `under_investigation` / applicability chưa rõ → `Cần xác minh`, ưu tiên ghi `(tạm)`.
- Direct dependency hoặc đã có bản vá không tự làm tăng ưu tiên. Ưu tiên không phải SLA.

`<Nếu có other_issues>` ⚠️ **Ngoài phạm vi dependency:** `<file>` phát hiện `<n>` issue khác (`<secret / misconfiguration>`, vị trí: `<path đã làm sạch>`). Xử lý theo luồng riêng; không tính vào số CVE.

---

## 3. Phân tích chi tiết

> Thẻ chi tiết cho mọi hàng `C` / `E` có quyết định **Cần xử lý**, sắp từ ưu tiên cao xuống thấp trong từng mục. P1-P2 dùng thẻ đầy đủ; P3 dùng thẻ rút gọn. Hàng `V` (cần xác minh / theo dõi) không có thẻ - xem mục 4. Có thể gom thẻ cho các package cùng thư viện cha hoặc cùng nhóm OS nếu phương án giống nhau (ghi đủ các mã, vd `C3 + C4`). Không chép mô tả dài của CVE.

### 3.1. CVE

#### `C<n>` · `<🔴 P1 | 🟠 P2>` · `<package/group>` `<current_version>` → `<minimum_fixed_version | ?>`

| Thuộc tính | Nội dung |
|---|---|
| **Vulnerability** | `<Canonical ID> (<severity>, <tiêu đề ngắn>)` · `<ID khác>` · `+N` · alias: `<CVE ↔ GHSA ↔ OSV | chưa xác minh>` |
| **Phát hiện ở** | `<file>`: `<vị trí>` · `<file>`: `<vị trí>` |
| **Applicability** | `<affected | not_affected | under_investigation | end_of_life | chưa xác minh>` · `<căn cứ>` |
| **Quyết định** | `<Cần xử lý>` - `<severity, KEV, EPSS, scope, lifecycle và căn cứ điều chỉnh priority>` |
| **Phụ thuộc** | `` `<app> → <parent> → <package>` `` · `<direct/transitive/không rõ>` (`<nguồn>`) · `<scope>` `<conflict nếu có>` |
| **Phạm vi ảnh hưởng** | `<[Dependency] | [Import] module/file | [Reachable] hàm lỗi>` · `<[Suy luận] tác động có thể nếu điều kiện nào>` |
| **Phương án** | `<Nâng direct | nâng parent | override/resolution tạm thời | rebuild/nâng base image | mitigation>` lên `<target>` - vá `<x/y>` (`<nguồn version vá>`) |
| **CVE chưa được xử lý** | `<ID và mitigation/theo dõi | Không, vá đầy đủ | Chưa xác minh>` |
| **Breaking change** | `<Thấp | Thấp-Trung bình | Trung bình | Cao | Chưa xác minh>` (`<changelog | release notes | migration guide | sơ bộ theo semver>`) - `<thay đổi hành vi, cấu hình, runtime cần chú ý>` |
| **Kiểm thử** | `1) <test gắn module/chức năng có bằng chứng> 2) <edge case theo advisory> 3) <container/build/runtime> 4) Quét lại Trivy và SBOM trên cùng candidate digest` |
| **Điều kiện đóng** | `<candidate digest đã quét>` · `<không còn version bị ảnh hưởng hoặc vendor xác nhận not_affected>` · `<regression test đạt>` · `<deployed digest = candidate digest nếu áp dụng>` |

`<Nếu có hai phương án>`
> **A - Cùng major:** `<version>` - vá `<x/y>`, còn `<ID>`. **B - Major mới:** `<version>` - vá `<x/y>`; breaking risk: `<nội dung>`.

`<Gói OS>` Tiêu đề `C<n> · <ưu tiên> · Base image <OS> - nhóm <source package> (<binary packages>)`. Dùng version vá của distro. Bỏ dòng Phụ thuộc; Phạm vi ghi `[Dependency] tiến trình trong container có thể dùng thư viện hệ thống này`. `will_not_fix` không tự hạ ưu tiên; nêu mitigation hoặc đổi/nâng base image.

`<Package ở base image / công cụ toàn cục>` Phương án ở base image hoặc Dockerfile; ghi rõ `overrides/resolutions` của app không tác động.

#### `C<n>` · 🟡 P3 · `<package>` `<current>` → `<target | ?>` *(thẻ rút gọn)*

| Thuộc tính | Nội dung |
|---|---|
| **Vulnerability** | `<ID (severity, tiêu đề ngắn)>` · `+N` |
| **Phát hiện ở** | `<file · vị trí>` |
| **Phương án** | `<hành động>` - vá `<x/y>` (`<nguồn>`) |
| **Breaking change / Kiểm thử** | `<mức (căn cứ)>` · `<1-2 test chính + quét lại>` |

### 3.2. EOL

> Thẻ cho hàng `E` có quyết định Cần xử lý và OS/runtime/framework đã hết hỗ trợ. `Bảo trì hạn chế` không đồng nghĩa với EOL. Package vừa có CVE vừa ngừng bảo trì chỉ có một thẻ ở mục này; nếu chỉ "bảo trì hạn chế" và có CVE thì nằm ở 3.1, thêm ghi chú lifecycle trong Quyết định.

#### `E<n>` · `<🔴 P1 | 🟠 P2>` · `<package/platform>` `<current_version>` → `<replacement | supported_cycle | ?>`

| Thuộc tính | Nội dung |
|---|---|
| **Tình trạng** | `<Ngừng bảo trì | Nhánh hết hỗ trợ | Bảo trì hạn chế | Chưa xác minh>` · `<ngày nếu có>` · nguồn: `<vendor/maintainer policy | endoflife.date | Uzomuzo>` |
| **Phát hiện ở** | `<file>`: `<vị trí>` |
| **CVE kèm theo** | `<Canonical ID (severity), trạng thái fix> | Không | Chưa xác minh` |
| **Quyết định** | `<Cần xử lý>` - `<lý do và căn cứ priority>` |
| **Phụ thuộc** | `` `<app> → <parent> → <package>` `` · `<direct/transitive/không rõ>` · `<scope>` |
| **Phạm vi ảnh hưởng** | `<[Dependency] | [Import] | [Reachable] | [Suy luận]> <bằng chứng và giới hạn>` |
| **Phương án** | `<Chuyển sang nhánh còn hỗ trợ | thay bằng package được bảo trì | nâng/rebuild base image>` · `<phương án thay thế chính nếu đã xác minh>` |
| **Breaking change** | `<mức>` (`<changelog/migration guide/sơ bộ theo semver>`) - `<API, config, runtime, plugin/peer dependency>` |
| **Kiểm thử** | `1) <luồng bị ảnh hưởng> 2) <migration/config/runtime> 3) <regression luồng chính> 4) Quét lại Trivy/SBOM/Uzomuzo` |
| **Điều kiện đóng** | `<nhánh/package/platform còn hỗ trợ>` · `<candidate digest hoặc lockfile đã xác minh>` · `<test đạt>` · `<scan mới không còn finding>` |

`<P3 EOL>` dùng thẻ rút gọn như 3.1 (Tình trạng · Phát hiện ở · Phương án · Breaking change / Kiểm thử).

---

## 4. Cần xác minh

> Chỉ liệt kê điểm còn thiếu bằng chứng có thể thay đổi quyết định, ưu tiên, phương án hoặc điều kiện đóng. Mỗi dòng là một hành động cụ thể. Ghi mã hàng liên quan ở mục 2.

| Mã | Mục | Thiếu gì | Vì sao ảnh hưởng kết luận | Cách xác minh | Owner đề xuất |
|:-:|---|---|---|---|---|
| `<C1 | V1 | ->` | `<artifact / package@version / CVE-ID>` | `<digest, alias, applicability, fix, relation, scope, usage, EOL, KEV/EPSS…>` | `<kết luận nào có thể thay đổi>` | `<một hành động hoặc lệnh đọc-only cụ thể>` | `<Web/App | Platform | Security | CI/Release | chưa xác định>` |

`<Nếu có source conflict>`
- `<Package>`: `<Nguồn A>` ghi `<direct/transitive/version>` nhưng `<Nguồn B>` ghi `<giá trị khác>`; xác minh bằng `<dependency tree / SBOM path / image inspection>`.

---

## Kiểm tra trước khi phát hành báo cáo

### Tổng quan và artifact
- [ ] Bảng 1.1 có đủ mỗi file input một hàng; file thiếu được ghi `✗` và nêu giới hạn.
- [ ] Số liệu trong 1.1 / 1.2 lấy từ `meta.input_files` và `stats` (không tự đếm lại).
- [ ] Đã đối chiếu deployed, Trivy và SBOM digest; chưa khớp hoặc chưa biết → `Preliminary`.
- [ ] Không dùng version từ source/lockfile/Dockerfile để khẳng định trạng thái image.
- [ ] Không kết luận "sạch" cho phần thiếu nguồn dữ liệu.

### Danh sách lỗi
- [ ] Mọi finding P1-P4 có trong mục 2, sắp đúng thứ tự ưu tiên; mã `C/E/V` khớp với thẻ ở mục 3 và dòng ở mục 4.
- [ ] Cột "Phát hiện ở" lấy từ `found_in` (file + vị trí), không suy đoán.
- [ ] Scanner record, ID, unique vulnerability và package bị ảnh hưởng được tách riêng; alias đã chuẩn hóa hoặc ghi `chưa xác định`.
- [ ] `not_affected` không nằm trong danh sách cần xử lý.
- [ ] Mọi version cần nâng lên có nguồn và ghi rõ vá `x/y`; không dùng `stable_version` của Uzomuzo.
- [ ] Project gốc không nằm trong bảng; package ở base image là hàng riêng với phạm vi `base-image tooling`.

### Phân tích chi tiết
- [ ] Mọi hàng `C`/`E` có quyết định Cần xử lý đều có thẻ; thẻ sắp từ P1 xuống P3 trong từng mục 3.1 / 3.2.
- [ ] Mọi phạm vi có nhãn `[Dependency]`, `[Import]`, `[Reachable]` hoặc `[Suy luận]`; không hạ ưu tiên chỉ vì không thấy import.
- [ ] Mỗi P1-P2 có một phương án chính, nguồn version đích, căn cứ breaking change, test cụ thể và điều kiện đóng.
- [ ] Transitive ưu tiên nâng parent; override/resolution ghi là tạm thời. Package ở base image xử lý tại base image. Gói OS dùng version vá của distro.
- [ ] `Bảo trì hạn chế` không bị viết thành EOL; nhánh hết hỗ trợ được phân biệt với dự án ngừng bảo trì.
- [ ] Không tuyên bố đã sửa, đã test hoặc đã deploy nếu chưa có evidence.

---

## Phụ lục - lấy dữ liệu cho từng trường từ `analysis.json`

| Trường trong template | Lấy từ |
|---|---|
| Bảng 1.1 (theo file input) | `meta.input_files[]`: Trivy → `records`, `distinct_ids`, `packages`, `by_severity`, `with_fixed_version`, `with_status`, `other_issues`, `flagged`; Uzomuzo → `entries`, `by_verdict`, `sbom_match`, `flagged`; SBOM → `packages_total`, `app_packages`, `os_packages`, `dependency_edges`, `artifact`, `digest`, `created`, `flagged`; KEV/EPSS → `entries`. Source code → `meta.usage_scan` |
| Đóng góp vào danh sách lỗi | `meta.input_files[].flagged` (số finding có file đó trong `found_in`) |
| Trạng thái báo cáo, Artifact, Thời điểm quét | `meta.report_status_suggested`, `meta.artifact_identity.*` |
| Số lượng lỗi | `stats.counting.*` (`unique_vulnerabilities = null` → "chưa xác định") |
| Theo ưu tiên / quyết định | `stats.rows_by_priority`, `stats.by_decision`, `stats.suppressed_cves` |
| Theo nhóm | đếm `findings[].section` và `install_location` ∈ {base-image tooling, image (global), image binary} |
| Không phát hiện vấn đề | `stats.no_findings` + `stats.no_findings_basis` (`null` → "không kết luận (thiếu nguồn)") |
| Độ phủ, cảnh báo | `meta.coverage.sources`, `meta.coverage.warnings` (chọn tối đa 3) |
| Mã hàng | thứ tự `findings[]` (đã sắp ưu tiên) + `section` (CVE → C, EOL → E, Xác minh/Khác hoặc decision ≠ Cần xử lý → V); nhóm OS dùng `os_groups[]` |
| Lỗi | `vulns[].id`, `vulns[].title` (CVE); `eol_status`, `eol_basis` (EOL); `verify[0]` (V) |
| Phát hiện ở | `found_in[]` (`file`, `locations`); theo từng CVE: `vulns[].sources` |
| Hiện tại / Cần nâng lên | `version` / `target_version` + `fix_summary`, `fix_coverage`; EOL → `eol_info.newest_supported_cycle` hoặc thư viện thay thế đã xác minh |
| Mức độ | `max_severity` + `active_vulns`; EOL → `eol_status` |
| Phạm vi | `scope_display` |
| Applicability | `vulns[].status`, `vulns[].applicability` |
| Quyết định (căn cứ) | `decision`, `priority_basis`, `exploit_context` |
| Phụ thuộc | `sbom.paths`, `relation`, `relation_basis`, `relation_conflict`, `scope` |
| Phạm vi ảnh hưởng | `usage.level`, `usage.modules`, `usage.limits`, `install_location`, `install_path` |
| Phương án | `remediation_hint`, `target_version`, `target_source`, `same_major_target` |
| CVE chưa được xử lý | `unfixed_ids`, `same_major_leaves_unfixed` |
| Breaking change | `upgrade_type`, `breaking_basis` (đổi thành "changelog" sau khi đã đọc) |
| Owner đề xuất | `owner_hint`; KEV/EPSS → Security; digest/artifact → CI/Release |
| Project gốc đã loại | `meta.root_packages`, `meta.root_hits` |
