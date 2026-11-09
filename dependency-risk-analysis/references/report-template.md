# Template báo cáo phân tích dependency

> **Cách dùng:** Giữ đúng thứ tự và tên các mục. Thay toàn bộ placeholder `<...>` bằng dữ liệu đã xác minh. Bỏ dòng hoặc mục không có dữ liệu thay vì để trống. Không đưa dữ liệu mẫu hoặc dữ liệu của một báo cáo khác vào template.
>
> **Nguyên tắc:** Chỉ ghi kết luận được nguồn dữ liệu hỗ trợ. Không suy ra trạng thái của image từ `package.json`, lockfile hoặc Dockerfile. Không gọi số record của scanner là số vulnerability duy nhất trước khi chuẩn hóa alias CVE/GHSA/OSV.

---

# Báo cáo phân tích thư viện - `<artifact/project>`

`<ngày báo cáo>` · Trivy: `<scanner_record_count | không có dữ liệu>` record · Vulnerability duy nhất: `<unique_vulnerability_count | chưa xác định>` · Uzomuzo: `<evaluated>/<total>` package · SBOM: `<package_count>` package

🔴 P1: `<n>` · 🟠 P2: `<n>` · 🟡 P3: `<n>` · ⚪ P4: `<n>` · ✅ Không phát hiện vấn đề: `<n | không kết luận (thiếu nguồn)>`

**Trạng thái báo cáo:** `<Preliminary | Verified | Closed>`

**Artifact identity:**

| Thuộc tính | Giá trị |
|---|---|
| Environment | `<production/staging/test/không rõ>` |
| Source revision | `<commit SHA | chưa xác định>` |
| Deployed image | `<registry/image:tag | chưa xác định>` |
| Deployed image digest | `<sha256:... | chưa xác định>` |
| Trivy target digest | `<sha256:... | chưa xác định>` |
| SBOM image digest | `<sha256:... | chưa xác định>` |
| Đối chiếu Trivy ↔ SBOM ↔ deployment | `<khớp | không khớp | chưa xác minh>` |
| Thời điểm Trivy scan | `<timestamp | chưa xác định>` |
| Thời điểm tạo SBOM | `<timestamp | chưa xác định>` |

**Độ phủ dữ liệu:** Trivy `<✓/✗>` · Trivy native JSON `<✓/✗>` · Uzomuzo `<✓/✗>` · SBOM `<✓/✗>` · KEV `<✓/✗>` · EPSS `<✓/✗>` · Source code `<✓/✗>` · Reachability `<✓/✗>`

- ⚠ `<Cảnh báo quan trọng nhất làm thay đổi kết luận>`
- ⚠ `<Cảnh báo quan trọng thứ hai>`
- ⚠ `<Cảnh báo quan trọng thứ ba>`

> Chỉ giữ tối đa ba cảnh báo. Nếu thiếu KEV/EPSS, ghi một lần tại đây rằng priority hiện là tạm thời. Nếu các digest chưa khớp, trạng thái báo cáo phải là `Preliminary`.

---

## 1. Tổng quan

| # | Thư viện / nhóm | Hiện tại → Đích | Loại | Mức độ / tình trạng | Ưu tiên | Quyết định | Phạm vi | Rủi ro nâng cấp |
|:-:|---|---|:-:|---|:-:|---|---|:-:|
| `<n>` | `<package hoặc nhóm OS>` | `<detected_version> → <minimum_fixed_version | nhánh còn hỗ trợ | thay thế | ?>` `<(vá x/y) nếu partial>` | `<CVE | EOL | CVE+EOL | Metadata | ->` | `<severity cao nhất và số vulnerability còn hiệu lực | trạng thái lifecycle>` | `<P1-P4>` `<(tạm) nếu cần xác minh applicability>` | `<Cần xử lý | Cần xác minh | Theo dõi | Không áp dụng>` | `<runtime | dev | test | build | optional | base-image tooling | không rõ>` | `<Thấp | Thấp-Trung bình | Trung bình | Cao | Chưa xác minh | ->` |

`<Nếu có suppressed>` **CVE vendor xác nhận không áp dụng:** `<n>` record, không đưa vào danh sách cần xử lý.

**Ghi chú cách đếm:**

- Scanner records: `<n>`.
- Vulnerability duy nhất sau khi chuẩn hóa alias: `<n | chưa xác định>`.
- Package bị ảnh hưởng: `<n>`.
- Advisory thiếu ID hoặc chưa chuẩn hóa alias: `<n | không có>`.

**Việc cần làm ngay:** `<Một đến hai câu, nêu hành động quyết định tiếp theo. Ưu tiên xác minh artifact digest, applicability hoặc thực hiện remediation cho P1-P2. Không tự đặt SLA nếu chưa có policy của tổ chức.>`

### Quy tắc cho bảng tổng quan

- Mọi finding P1-P4 phải xuất hiện trong bảng; không ẩn P1-P2.
- Sắp theo priority, sau đó severity hoặc mức độ lifecycle.
- Mỗi package một hàng; gói OS gộp theo source package hoặc cùng phương án xử lý.
- `Hiện tại → Đích` phải dùng **minimum fixed version** từ Trivy, OSV, GHSA, advisory hoặc distro tracker. Không dùng `stable_version` của Uzomuzo làm version vá.
- Nếu bản đích chỉ vá một phần, ghi `(vá x/y)` và không viết “đã vá”.
- Nếu chưa xác định version đích, ghi `→ ?`.
- `not_affected` không được tính là cần xử lý. `under_investigation` hoặc applicability chưa rõ phải ghi `Cần xác minh`.
- Thiếu Trivy hoặc Uzomuzo thì không được kết luận “không phát hiện vấn đề” cho phạm vi tương ứng.
- Direct dependency hoặc đã có bản vá không tự làm tăng priority.
- Priority không phải SLA và template không tự sinh deadline.

---

## 2. Chi tiết CVE

> Chỉ tạo thẻ cho P1-P2 có `section = CVE`. Có thể gom các finding cùng package, cùng thư viện cha hoặc cùng nhóm OS nếu phương án xử lý giống nhau. Mỗi thẻ khoảng 7 đến 9 dòng. Không chép lại mô tả dài của CVE.

### `<🔴 P1 | 🟠 P2>` · `<package/group>` `<detected_version>` → `<minimum_fixed_version | ?>`

| Thuộc tính | Nội dung |
|---|---|
| **Vulnerability** | `<Canonical CVE/GHSA-ID> (<severity>, <tiêu đề ngắn>) · <ID khác> · +N` |
| **Alias / chuẩn hóa ID** | `<CVE ↔ GHSA ↔ OSV aliases | chưa xác minh>`; scanner records: `<n>`, unique vulnerabilities: `<n | chưa xác định>` |
| **Applicability** | `<affected | not_affected | under_investigation | end_of_life | chưa xác minh>` · `<căn cứ>` |
| **Quyết định** | `<Cần xử lý | Cần xác minh>` - `<severity, KEV, EPSS, scope, lifecycle và căn cứ điều chỉnh priority>` |
| **Phụ thuộc** | `` `<app> → <parent> → <package>` `` · `<direct/transitive/không rõ>` (`<nguồn>`) · `<scope>` `<nêu conflict nếu các nguồn mâu thuẫn>` |
| **Phạm vi ảnh hưởng** | `<[Dependency] có trong SBOM | [Import] module/file | [Reachable] hàm lỗi>` · `<[Suy luận] tác động có thể xảy ra nếu điều kiện nào>` |
| **Phương án** | `<Nâng direct | nâng parent | override/resolution tạm thời | rebuild/nâng base image | mitigation>` lên `<target>` - vá `<x/y>` vulnerability (`<nguồn version vá>`) |
| **CVE chưa được xử lý** | `<ID và mitigation/theo dõi | Không, fix coverage đầy đủ | Chưa xác minh>` |
| **Breaking change** | `<Thấp | Thấp-Trung bình | Trung bình | Cao | Chưa xác minh>` (`<changelog | release notes | migration guide | sơ bộ theo semver>`) - `<thay đổi hành vi, cấu hình hoặc runtime cần chú ý>` |
| **Kiểm thử** | `1) <test gắn với module/chức năng có bằng chứng> 2) <edge case liên quan advisory> 3) <container/build/runtime test> 4) Quét lại Trivy và SBOM trên cùng candidate digest` |
| **Điều kiện đóng** | `<Candidate digest đã quét>` · `<version bị ảnh hưởng không còn hoặc vendor xác nhận not_affected>` · `<regression test đạt>` · `<deployed digest khớp candidate digest nếu áp dụng>` |

`<Nếu có hai phương án>`

> **A - Cùng major:** `<version>` - vá `<x/y>`, còn `<ID>`. **B - Major mới:** `<version>` - vá `<x/y>`; breaking risk: `<nội dung>`.

`<Nếu là gói OS>`

- Tiêu đề: `Base image <OS> - nhóm <source package> (<binary package...>)`.
- Dùng version vá của distro, không dùng upstream version.
- Bỏ dòng `Phụ thuộc`; phạm vi ghi `[Dependency] tiến trình trong container có thể dùng thư viện hệ thống này`.
- Nếu distro ghi `will_not_fix`, không tự hạ priority; nêu mitigation hoặc phương án đổi/nâng base image.

---

## 3. Chi tiết EOL

> Tạo thẻ cho P1-P2 có `section = EOL` và OS/runtime/framework đã hết hỗ trợ. `Limited maintenance` không đồng nghĩa với EOL. Package vừa có CVE vừa ngừng bảo trì chỉ tạo một thẻ tại mục này; nếu chỉ “bảo trì hạn chế” và có CVE thì để tại mục 2, thêm ghi chú lifecycle trong quyết định.

### `<🔴 P1 | 🟠 P2>` · `<package/platform>` `<current_version>` → `<replacement | supported_cycle | ?>`

| Thuộc tính | Nội dung |
|---|---|
| **Tình trạng** | `<Ngừng bảo trì | Nhánh hết hỗ trợ | Bảo trì hạn chế | Chưa xác minh>` · `<ngày nếu có>` · nguồn: `<vendor/maintainer policy | endoflife.date bổ sung | advisory>` |
| **CVE kèm theo** | `<Canonical ID (severity), trạng thái fix> | Không | Chưa xác minh` |
| **Quyết định** | `<Cần xử lý | Cần xác minh | Theo dõi>` - `<lý do và căn cứ priority>` |
| **Phụ thuộc** | `` `<app> → <parent> → <package>` `` · `<direct/transitive/không rõ>` · `<scope>` |
| **Phạm vi ảnh hưởng** | `<[Dependency] | [Import] | [Reachable] | [Suy luận]> <bằng chứng và giới hạn>` |
| **Phương án** | `<Chuyển sang nhánh còn hỗ trợ | thay bằng package được bảo trì | nâng/rebuild base image | theo dõi>` · `<phương án thay thế chính nếu đã xác minh>` |
| **Breaking change** | `<mức>` (`<changelog/migration guide/sơ bộ theo semver>`) - `<API, config, runtime hoặc plugin/peer dependency cần chú ý>` |
| **Kiểm thử** | `1) <luồng bị ảnh hưởng> 2) <migration/config/runtime> 3) <regression luồng nghiệp vụ chính> 4) Quét lại Trivy/SBOM/Uzomuzo` |
| **Điều kiện đóng** | `<Nhánh/package/platform còn hỗ trợ>` · `<candidate digest hoặc lockfile đã được xác minh>` · `<test đạt>` · `<scan mới không còn finding tương ứng>` |

---

## 4. Cần xác minh

> Chỉ liệt kê điểm còn thiếu bằng chứng có thể thay đổi quyết định, priority, phương án hoặc điều kiện đóng. Mỗi dòng phải là một hành động cụ thể.

| Mục | Thiếu gì | Vì sao ảnh hưởng kết luận | Cách xác minh | Owner đề xuất |
|---|---|---|---|---|
| `<artifact/package@version/CVE-ID>` | `<digest, alias, applicability, fix, relation, scope, usage, EOL, KEV/EPSS...>` | `<kết luận nào có thể thay đổi>` | `<một hành động hoặc lệnh đọc-only cụ thể>` | `<Web/App | Platform | Security | CI/Release | chưa xác định>` |

`<Nếu có source conflict>`

- `<Package>`: `<Nguồn A>` ghi `<direct/transitive/version>` nhưng `<Nguồn B>` ghi `<giá trị khác>`; xác minh bằng `<dependency tree/SBOM path/image inspection>`.

`<Nếu có other_issues>`

> ⚠️ **Ngoài phạm vi dependency:** Trivy phát hiện `<n>` issue khác (`<secret/misconfiguration/license nếu có vấn đề>`, vị trí: `<path đã làm sạch>`). Theo dõi bằng luồng xử lý riêng; không trộn vào số CVE dependency.

---

## Kiểm tra trước khi phát hành báo cáo

### Dữ liệu và artifact

- [ ] Đã ghi rõ nguồn có và thiếu.
- [ ] Đã đối chiếu deployed, Trivy và SBOM image digest; nếu chưa khớp, báo cáo là `Preliminary`.
- [ ] Không dùng version từ source/lockfile/Dockerfile để khẳng định trạng thái deployed image.
- [ ] Không kết luận “sạch” cho phần thiếu nguồn dữ liệu.

### Vulnerability

- [ ] Scanner record count, unique vulnerability count và affected package count được tách riêng.
- [ ] CVE/GHSA/OSV alias đã được chuẩn hóa hoặc đánh dấu `chưa xác minh`.
- [ ] Advisory thiếu ID không được tính vào unique vulnerability count.
- [ ] `not_affected` không nằm trong danh sách cần xử lý.
- [ ] Mọi target version có nguồn và ghi rõ vá `x/y` vulnerability.
- [ ] Không dùng `stable_version` của Uzomuzo làm bản vá.

### Phạm vi và priority

- [ ] Mọi phạm vi có nhãn `[Dependency]`, `[Import]`, `[Reachable]` hoặc `[Suy luận]`.
- [ ] Không hạ priority chỉ vì không tìm thấy import.
- [ ] Severity được tách khỏi priority.
- [ ] Việc thiếu KEV/EPSS chỉ được cảnh báo một lần ở phần độ phủ dữ liệu.
- [ ] Priority không được trình bày như SLA hoặc deadline.

### Remediation và kiểm thử

- [ ] Mỗi P1-P2 có một phương án chính, nguồn version đích, breaking-change basis và test cụ thể.
- [ ] Dependency transitive ưu tiên nâng parent; override/resolution được ghi là tạm thời.
- [ ] Package của base image được xử lý tại base image, không coi application override là đã vá.
- [ ] Gói OS dùng version vá của distro.
- [ ] Không tuyên bố đã sửa, đã test hoặc đã deploy nếu chưa có evidence.
- [ ] Điều kiện đóng dựa trên scan/SBOM của candidate artifact và đối chiếu deployed digest khi áp dụng.

### EOL

- [ ] `Limited maintenance` không bị viết thành EOL.
- [ ] Nhánh hết hỗ trợ được phân biệt với dự án ngừng bảo trì.
- [ ] Coverage gap của công cụ EOL được nêu rõ.
- [ ] Lifecycle của OS, runtime và framework được kiểm tra theo chính sách vendor/maintainer; nguồn bổ sung được ghi rõ.

---

## Phụ lục - lấy dữ liệu cho từng trường từ `analysis.json`

| Trường trong template | Lấy từ |
|---|---|
| `scanner_record_count`, vulnerability duy nhất, package bị ảnh hưởng, advisory thiếu ID | `stats.counting.scanner_records` / `unique_vulnerabilities` (`null` → "chưa xác định") / `affected_packages` / `advisories_without_id` |
| Uzomuzo `<evaluated>/<total>` | `meta.coverage.packages.lifecycle_covered` / `meta.coverage.packages.app` |
| SBOM `<package_count>` | `meta.coverage.packages.total` (đã loại project gốc và node Application/Container/OS) |
| P1-P4 | `stats.rows_by_priority` |
| Không phát hiện vấn đề | `stats.no_findings` + `stats.no_findings_basis`; `null` → "không kết luận (thiếu nguồn)" |
| Trạng thái báo cáo | `meta.report_status_suggested` (Verified chỉ khi Trivy ↔ SBOM ↔ deployment khớp digest) |
| Artifact identity | `meta.artifact_identity.*` (environment, source_revision, deployed_* lấy từ tham số `--environment`, `--revision`, `--deployed-image`, `--deployed-digest`) |
| Độ phủ dữ liệu, cảnh báo | `meta.coverage.sources`, `meta.coverage.warnings` (chọn tối đa 3) |
| Cột **Phạm vi** | `scope_display` (runtime / dev / test / build / optional / base-image tooling / image (global) / image binary / không rõ) |
| Cột **Quyết định** | `decision` (`Không áp dụng` = finding chỉ có CVE trong `suppressed`) |
| Hiện tại → Đích, (vá x/y) | `version` → `target_version`, `fix_summary`, `fix_coverage` |
| Vulnerability, Alias | `vulns[].id`, `vulns[].aliases`, `vulns[].alias_checked` |
| Applicability | `vulns[].status`, `vulns[].applicability` |
| Quyết định (căn cứ) | `priority_basis`, `exploit_context` |
| Phụ thuộc | `sbom.paths`, `relation`, `relation_basis`, `relation_conflict`, `scope` |
| Phạm vi ảnh hưởng | `usage.level`, `usage.modules`, `usage.limits`, `install_location`, `install_path` |
| Phương án | `remediation_hint` + `target_version`, `target_source`, `same_major_target` |
| CVE chưa được xử lý | `unfixed_ids`, `same_major_leaves_unfixed` |
| Breaking change | `upgrade_type`, `breaking_basis` (cập nhật thành "changelog" sau khi đã đọc) |
| Owner đề xuất (mục 4) | `owner_hint` (Platform cho OS / base image, Web/App cho dependency của app); KEV/EPSS → Security; digest → CI/Release |
| Project gốc đã loại | `meta.root_packages`, `meta.root_hits` |
