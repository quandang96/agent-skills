# Upgrade playbook

## 0. Nguồn tra cứu khi cần xác minh

| Cần biết | Nguồn |
|---|---|
| Bản vá của CVE (thư viện ứng dụng) | OSV (osv.dev), GitHub Advisory (GHSA), advisory của thư viện |
| Bản vá gói OS | Security tracker của distro: security-tracker.debian.org, ubuntu.com/security/cves, security.alpinelinux.org, access.redhat.com/security |
| Đang bị khai thác thực tế | CISA KEV catalog (cisa.gov/known-exploited-vulnerabilities-catalog) |
| Xác suất bị khai thác trong 30 ngày | EPSS (first.org/epss) - là xác suất khai thác, không phải điểm rủi ro của ứng dụng |
| Code có gọi tới hàm lỗi không | Go: `govulncheck -json ./...`; ecosystem khác: đọc advisory xem hàm/tính năng bị lỗi rồi grep |
| Nhánh version còn được hỗ trợ không | Chính sách lifecycle của vendor/maintainer (trang release/support policy); endoflife.date là nguồn bổ sung |
| Breaking change | CHANGELOG / GitHub Releases / migration guide của thư viện |

Ghi nguồn ngắn trong thẻ (vd "bản vá: OSV"). Không tra được → "Chưa xác minh", đưa vào mục Cần xác minh.

## 1. Chọn cách xử lý

| Tình huống | Cách xử lý | Ghi chú |
|---|---|---|
| Direct dep, có fix | Nâng trực tiếp lên `target_version` | Cách sạch nhất |
| Transitive, parent đã có bản mới kéo version vá | Nâng parent (thư viện direct trong `sbom.paths`) | Ưu tiên - không tạo override phải gỡ sau |
| Transitive, parent chưa vá / nâng parent là major | Ép version transitive (bảng mục 2) | Ghi chú gỡ override khi parent cập nhật |
| Không có bản fix (đã xác nhận) | Giảm thiểu đúng điều kiện khai thác của CVE: không dùng hàm/tính năng bị lỗi, validate input, giới hạn mạng/WAF; hoặc thay thư viện | Nêu rủi ro còn lại; theo dõi khi có bản vá |
| Chưa biết có bản fix không | Tra nguồn ở mục 0 trước khi đề xuất | Không đoán version |
| Bản vá chỉ phủ một phần (`fix_coverage = partial`) | Nâng lên `target_version` cho CVE đã có fix + xử lý riêng CVE còn sót (mitigation / theo dõi bản vá) | Không ghi "đã vá" |
| Gói OS `will_not_fix` / `affected` (không có fix) | Đọc distro tracker: nếu `not-affected` → ghi lý do; nếu thật sự bị ảnh hưởng → đánh giá điều kiện khai thác, mitigation, hoặc đổi base image (distroless / slim / distro khác có bản vá) | **Không tự hạ ưu tiên** chỉ vì vendor không vá |
| Trivy status `end_of_life` | Distro/gói hết hỗ trợ → nâng base image lên release còn hỗ trợ | Chưa chắc đã bị ảnh hưởng, nhưng sẽ không có bản vá |
| Dự án ngừng bảo trì (archived / disabled / `replace`) | Thay bằng thư viện đang được bảo trì | Nêu 1 thư viện thay thế chính |
| Nhánh version hết hỗ trợ, dự án vẫn phát triển (vd Vue 2, Node 16) | Chuyển sang nhánh còn hỗ trợ (`eol_info.newest_supported_cycle`) theo migration guide | Không phải thay thư viện |
| Ít commit / `Stalled` nhưng vẫn ra bản vá bảo mật | Bảo trì hạn chế → theo dõi, lên kế hoạch dài hạn | Không xếp vào "ngừng bảo trì" |
| Gói OS (deb/rpm/apk) có fix | Rebuild image hoặc nâng base image tag | Gom theo `os_groups`, không nâng từng gói |
| Package trong công cụ của base image (`install_location = base-image tooling`, vd `usr/local/lib/node_modules/npm/node_modules/undici`) | Nâng base image (vd `node:<version mới>`), hoặc `npm install -g npm@<ver>` trong Dockerfile, hoặc loại npm/yarn khỏi runtime image (multi-stage, distroless) | `overrides`/`resolutions` của app **không** tác động; quét lại image để xác nhận |
| Package cài toàn cục trong image (`image (global)`, vd pm2) hoặc nằm trong binary (`image binary`) | Cập nhật ở bước Dockerfile/base image cài package hoặc binary đó | Không thuộc lockfile của app |
| Uzomuzo `review` (thiếu dữ liệu, vd package nội bộ) | Kiểm tra thủ công nguồn gốc/registry | Không ảnh hưởng quyết định xử lý CVE của package đó |

## 1b. An toàn chuỗi cung ứng khi nâng cấp

Bản "vá" cũng có thể là rủi ro (package bị chiếm quyền, typosquat, bản vừa phát hành có mã độc). Khi đề xuất phương án, kèm các lưu ý sau ở mức 1 dòng nếu liên quan:

- Ghim **version chính xác** (không dùng `latest`, `^`/`~` rộng cho bản vá bảo mật); commit lockfile và review diff lockfile trong MR.
- Kiểm tra bản đích được phát hành bởi maintainer quen thuộc. Cẩn thận với bản vừa phát hành vài giờ/ngày, hoặc đổi maintainer. Có thể dùng `npm audit signatures`, provenance của npm/PyPI, checksum của Go (`go.sum`, sum.golang.org).
- Tên package thay thế phải đúng tên chính chủ (tránh typosquat, vd `axios` chứ không phải `axois`).
- Thử nâng cấp trong nhánh riêng/CI; với npm có thể cài thử bằng `--ignore-scripts` để tránh chạy lifecycle script lạ khi chưa review.
- Ép version transitive (overrides/resolutions) là biện pháp tạm: ghi chú lý do + CVE, gỡ khi thư viện cha đã cập nhật.

## 2. Ép version transitive theo ecosystem

| Ecosystem | Cách |
|---|---|
| npm | `"overrides": { "qs": "6.7.3" }` trong package.json |
| yarn | `"resolutions": { "qs": "6.7.3" }` |
| pnpm | `"pnpm": { "overrides": { "qs": "6.7.3" } }` |
| Maven | `<dependencyManagement>` khai báo version; hoặc `<exclusions>` + khai báo trực tiếp |
| Gradle | `constraints { implementation("g:a:ver") { because("CVE-...") } }` |
| pip / poetry | Ghim trong constraints.txt / `[tool.poetry.dependencies]` |
| Go | `go get module@ver` rồi `go mod tidy` (MVS sẽ chọn bản cao hơn) |
| NuGet | Thêm PackageReference trực tiếp với version vá (Central Package Management: `CentralPackageTransitivePinningEnabled`) |
| Cargo | `cargo update -p crate --precise ver` |

## 3. Rủi ro breaking change theo loại nâng cấp

Mức dưới đây chỉ là **đánh giá sơ bộ**. Với mọi mục P1-P2, kể cả patch, lướt changelog/release notes trong khoảng version hiện tại → đích để tìm thay đổi hành vi, giá trị mặc định, runtime/engine tối thiểu. Ghi căn cứ trong thẻ: "(changelog)" hoặc "(sơ bộ theo semver)".

| `upgrade_type` | Mức sơ bộ | Cần kiểm tra |
|---|---|---|
| patch | Thấp | Thay đổi hành vi trong bản vá bảo mật (vd siết validate input, đổi encode), `engines`/runtime tối thiểu |
| minor | Thấp-Trung bình | Changelog: deprecation, thay đổi default, phiên bản runtime tối thiểu |
| minor-0x (0.x) | Trung bình | Theo semver, 0.x minor được phép breaking → đọc changelog |
| major | Cao | Migration guide: API bị xóa/đổi tên, ESM/CJS, Java/Node/Python tối thiểu, config format, dependency peer |
| os-patch | Thấp | Bản vá distro cùng release; rủi ro chủ yếu nếu nâng base image sang major OS mới |
| Thay thư viện | Cao | API khác hoàn toàn → liệt kê điểm gọi cần sửa |

Nâng mức rủi ro thêm 1 bậc nếu: thư viện là framework lõi (Spring, Express, Django, React...), dùng ở nhiều module, hoặc có plugin/peer dependency phụ thuộc version.

## 4. Gợi ý hạng mục kiểm thử theo loại thư viện

Chọn 3-5 mục phù hợp nhất, viết thành tình huống cụ thể của ứng dụng.

| Loại thư viện | Hạng mục kiểm thử |
|---|---|
| Web framework / router / body parser | Route chính, query/body lồng nhau, upload file, redirect, error handler, middleware order |
| HTTP client (axios, okhttp, requests) | Gọi API ngoài thành công/timeout/retry, proxy, redirect, header auth, xử lý lỗi 4xx/5xx |
| Serialization (jackson, gson, yaml, xml) | Serialize/deserialize DTO chính, field null/unknown, date format, payload lớn |
| Logging (log4j, logback, winston) | Log ra đúng appender/format, rotation, mask dữ liệu nhạy cảm |
| Auth / crypto / JWT / TLS (openssl, jsonwebtoken, bouncycastle) | Login, refresh token, verify chữ ký, kết nối TLS tới DB/API ngoài, cert chain |
| DB driver / ORM | Kết nối pool, transaction, migration, query nặng, kiểu dữ liệu date/decimal |
| Utility (lodash, commons-*, moment) | Các hàm thực tế được gọi (grep), định dạng ngày/giờ, locale, timezone |
| Template / parser (handlebars, markdown, xml) | Render template chính, escape HTML, input đặc biệt |
| Gói OS / base image | Container khởi động, healthcheck, TLS outbound, timezone/locale, công cụ shell dùng trong entrypoint |

Luôn thêm: **quét lại Trivy/SBOM xác nhận CVE đã hết** và, nếu là major/thay thư viện, **regression test các luồng nghiệp vụ chính** có dùng thư viện.
