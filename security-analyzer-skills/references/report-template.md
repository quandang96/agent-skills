# Template báo cáo

Giữ đúng thứ tự và tên mục. Thay `<...>` bằng dữ liệu; bỏ dòng/mục không có dữ liệu thay vì để trống.

| Mục | Nội dung | Lấy từ |
|---|---|---|
| Độ phủ dữ liệu | Nguồn có/thiếu + tối đa 3 cảnh báo làm thay đổi kết luận | `meta.coverage` |
| 1. Tổng quan | Mọi thư viện P1-P4, mỗi hàng 1 thư viện / 1 nhóm OS | `findings`, `os_groups` |
| 2. Chi tiết CVE | Thẻ P1-P2 có `section = CVE` | |
| 3. Chi tiết EOL | Thẻ P1-P2 có `section = EOL` + OS/runtime/framework hết hỗ trợ | `meta.platform_eol` |
| 4. Cần xác minh | Các `verify[]` còn mở - mỗi dòng 1 việc cụ thể | `verify` |

````markdown
# Báo cáo phân tích thư viện - <artifact/project>

<ngày> · Trivy <n> CVE · Uzomuzo <n> package · SBOM <n> package
🔴 P1: <n> · 🟠 P2: <n> · 🟡 P3: <n> · ⚪ P4: <n> · ✅ Không phát hiện vấn đề: <n | "không kết luận (thiếu nguồn)">

**Độ phủ dữ liệu:** Trivy ✓ · Uzomuzo ✓ · SBOM ✓ · KEV ✗ · EPSS ✗ · Source code ✓ · Trivy↔SBOM: khớp
- ⚠ <cảnh báo quan trọng nhất, vd "Chưa đối chiếu KEV/EPSS → ưu tiên P1-P2 là tạm thời">
- ⚠ <...> (tối đa 3)

## 1. Tổng quan

| # | Thư viện | Hiện tại → Đích | Loại | Mức độ | Ưu tiên | Quyết định | Rủi ro nâng cấp |
|:-:|---|---|:-:|---|:-:|---|:-:|
| 1 | <tên> | <ver> → <ver> | CVE | CRITICAL (2 CVE) | 🔴 P1 | Cần xử lý | Thấp |
| 2 | <tên> | <ver> → <ver> (vá 1/2) | CVE | HIGH (2 CVE) | 🟠 P2 | Cần xử lý | Trung bình |
| 3 | <tên> | <ver> → thay thế | EOL | Ngừng bảo trì, 1 CVE không có bản vá | 🟠 P2 | Cần xử lý | Cao |
| 4 | <tên> | <ver> → nhánh <x> | EOL | Nhánh <y> hết hỗ trợ <ngày> | 🟠 P2 | Cần xử lý | Cao |
| 5 | <tên> | <ver> → ? | CVE | HIGH (1 CVE), vendor đang điều tra | 🟠 P2 (tạm) | Cần xác minh | - |

<Nếu có suppressed> CVE vendor xác nhận không áp dụng (not_affected): <n> - không cần xử lý.

**Việc cần làm ngay:** <1-2 câu: hành động quan trọng nhất; gom các mục rủi ro thấp vào cùng một MR>

## 2. Chi tiết CVE

### 🔴 P1 · <tên> <ver hiện tại> → <ver đích>

| | |
|---|---|
| **CVE** | <CVE-ID> (<SEV>, <tiêu đề ngắn>) · <CVE-ID> (...) · +N |
| **Quyết định** | Cần xử lý - <căn cứ ưu tiên: severity/KEV/EPSS/scope, 1 câu> |
| **Phụ thuộc** | `<app> → <parent> → <lib>` · <direct/transitive (nguồn)> · <scope nếu không phải runtime> |
| **Phạm vi ảnh hưởng** | [Import] <module (số file)> · [Reachable] <hàm> · [Dependency] chỉ có trong SBOM · [Suy luận] có thể ảnh hưởng <...> |
| **Phương án** | <hành động cụ thể> - vá <x/y> CVE (nguồn: <Trivy/OSV/advisory>) |
| **Breaking change** | <Thấp/Trung bình/Cao> (<changelog / sơ bộ theo semver>) - <thay đổi cụ thể> |
| **Kiểm thử** | 1) <...> 2) <...> 3) <...> 4) Quét lại Trivy: hết <CVE> |

<Nâng major: thêm 1 dòng dưới thẻ>
> **A:** <ver cùng major> - vá <CVE>, còn sót <CVE>. **B:** <ver major mới> - vá hết; breaking: <...>.

<Gói OS: 1 thẻ / nhóm source, tiêu đề "Base image <os> - nhóm <source> (<gói1>, <gói2>)"; bỏ dòng Phụ thuộc;
 Phạm vi = "[Dependency] mọi tiến trình trong container dùng <lib>". Không có bản vá (will_not_fix/affected):
 Phương án = mitigation cụ thể hoặc đổi base image/distro, không tự hạ ưu tiên.>

## 3. Chi tiết EOL

### 🟠 P2 · <tên> <ver hiện tại> → <thay thế | nhánh còn hỗ trợ>

| | |
|---|---|
| **Tình trạng** | <Ngừng bảo trì: archived/replace... | Nhánh <x> hết hỗ trợ <ngày> (nguồn) | ...> |
| **CVE kèm theo** | <CVE-ID (SEV), không có bản vá> hoặc "Không" |
| **Quyết định** | Cần xử lý - <lý do 1 câu> |
| **Phụ thuộc** | `<app> → <lib>` · <direct/transitive> |
| **Phạm vi ảnh hưởng** | [Import]/[Dependency]/[Suy luận] <...> |
| **Phương án** | <Chuyển sang nhánh <x> còn hỗ trợ | Thay bằng <thư viện> (<lý do ngắn>)> |
| **Breaking change** | <mức> (<căn cứ>) - <điểm khác API/cấu hình chính> |
| **Kiểm thử** | 1) <...> 2) <...> 3) Quét lại Trivy/Uzomuzo |

<Thư viện "Bảo trì hạn chế" có CVE nằm ở mục 2; thêm 1 câu ghi chú vào ô Quyết định.
 OS/runtime hết hỗ trợ (meta.platform_eol): 1 thẻ "<OS/runtime> <version> → <bản còn hỗ trợ>".>

## 4. Cần xác minh

| Mục | Thiếu gì | Cách xác minh |
|---|---|---|
| <lib@ver> | <1 cụm từ> | <1 hành động cụ thể> |

<Nếu có other_issues, 1 dòng cuối> ⚠️ Ngoài thư viện: Trivy phát hiện <n> issue khác (<loại>: <path>) - cần xử lý riêng.
````

## Quy tắc cho bảng tổng quan

- Sắp theo ưu tiên rồi mức độ. Gói OS gộp theo nhóm source, 1 hàng/nhóm. Số đếm ở dòng đầu dùng `stats.rows_by_priority`.
- **✅ Không phát hiện vấn đề:** dùng `stats.no_findings`; nếu là `null` (thiếu Trivy hoặc Uzomuzo) ghi "không kết luận (thiếu nguồn)".
- **Hiện tại → Đích:** đích chưa xác định ghi `→ ?`; vá chưa hết ghi `(vá x/y)`; nhiều phương án ghi `A / B`.
- **Loại:** `CVE`, `EOL`, `CVE+EOL` (CVE + bảo trì hạn chế), `-` (chỉ thiếu dữ liệu).
- **Mức độ:** CVE → severity cao nhất + số CVE còn hiệu lực; EOL → Ngừng bảo trì / Nhánh hết hỗ trợ / Bảo trì hạn chế.
- **Ưu tiên:** thêm "(tạm)" khi `decision = Cần xác minh`. Việc thiếu KEV/EPSS chỉ nêu một lần ở dòng độ phủ dữ liệu.
- **Rủi ro nâng cấp:** theo `upgrade_type` + changelog đã tra; `-` nếu chưa có phương án.

## Ví dụ một thẻ hoàn chỉnh (độ dài chuẩn)

### 🟠 P2 · qs 6.7.0 → 6.7.3

| | |
|---|---|
| **CVE** | CVE-2022-24999 (HIGH, Prototype pollution) |
| **Quyết định** | Cần xử lý - HIGH, parse query string của mọi request (KEV/EPSS chưa kiểm tra) |
| **Phụ thuộc** | `app → express@4.17.1 → qs` và `app → request@2.88.2 → qs` · transitive (SBOM; Uzomuzo ghi direct → `npm ls qs`) |
| **Phạm vi ảnh hưởng** | [Import] qua express: `server` (1 file); qua request: `server/services` (1 file) |
| **Phương án** | Nâng express lên 4.21.x (kéo qs đã vá); nhánh request hết khi thay request (mục 3) - vá 1/1 CVE (OSV) |
| **Breaking change** | Thấp (sơ bộ theo semver) - chưa xem changelog express |
| **Kiểm thử** | 1) API có query lồng nhau `?a[b]=1` 2) Form POST urlencoded 3) Quét lại Trivy: hết CVE-2022-24999 |
