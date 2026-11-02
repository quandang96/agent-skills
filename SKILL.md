---
name: it-scenario-review
description: Review IT項目書 / test scenario viết theo template (概要, 対象画面, 表示データの取得元, 非表示条件, 前提条件, bảng test case 11 cột) bằng cách đối chiếu với requirement (text, có thể kèm ảnh design). Báo sai sót, thiếu case kèm vị trí và tham chiếu. Dùng khi người dùng gửi scenario/項目書 và yêu cầu review, check coverage hoặc tìm case còn thiếu.
---

# Review IT項目書 / Test Scenario

Skill này review một bộ test scenario viết theo template IT項目書 (ví dụ: `036.023_IT項目書_B018-150883`) và đối chiếu với requirement, có hoặc không có ảnh design. Mục tiêu là tìm ra:

- Chỗ **sai** so với requirement hoặc design
- Chỗ **thiếu** (requirement chưa có case, thiếu case 準正常, thiếu boundary)
- Chỗ **không nhất quán** giữa các phần trong chính 項目書
- Chỗ **không đúng format** template

Mọi phát hiện đều phải có **vị trí trong scenario** và **tham chiếu tới requirement/design/template**.

---

## 1. Input

| Input | Bắt buộc | Ghi chú |
|---|---|---|
| Scenario / 項目書 | Có | Markdown, Confluence export, Excel, paste text |
| Requirement | Nên có | Markdown, text, PDF, ticket |
| Ảnh design | Không | Một hoặc nhiều ảnh màn hình, Figma export |

Cách xử lý input:

- **Excel**: đọc bằng pandas/openpyxl, giữ tên sheet và số dòng gốc để làm vị trí tham chiếu.
- **PDF/docx**: trích text, giữ số trang hoặc heading.
- **Ảnh design**: mở và xem từng ảnh. Đánh số ảnh theo thứ tự nhận được (Ảnh 1, Ảnh 2…). Nếu ảnh mờ hoặc không đọc được chữ, ghi rõ trong phần Tóm tắt, không đoán.
- **Không có requirement**: vẫn review phần A (format) và B (nhất quán nội bộ), bỏ qua phần C, ghi rõ giới hạn này trong Tóm tắt. Không tự bịa requirement.
- **Không có design**: bỏ qua phần D, ghi "Design: Không có".

---

## 2. Quy ước vị trí tham chiếu

Dùng thống nhất các ký hiệu sau trong toàn bộ output:

| Ký hiệu | Ý nghĩa | Ví dụ |
|---|---|---|
| `§n` | Section trong 項目書 theo template | `§3 表示データの取得元`, `§5 非表示条件` |
| `TC#n` | Test case theo cột STT | `TC#12` |
| `TC#n/<cột>` | Cột cụ thể của test case | `TC#12/期待結果`, `TC#7/前提条件` |
| `Sau TC#n` | Vị trí đề xuất chèn case mới | `Sau TC#15` |
| `REQ-nn` | Mục requirement đã trích xuất | `REQ-04` |
| `DSN-nn` | Phần tử UI trích từ design | `DSN-03 (Ảnh 2, vùng 検索条件)` |
| `TPL §x` | Quy định của template | `TPL §11.1 (11 cột)` |

Với Excel, thêm vị trí gốc: `Sheet "テスト項目" dòng 25 (TC#12)`.

Mỗi `REQ-nn` phải ghi nguồn gốc trong requirement (heading, số trang, hoặc đoạn trích ngắn dưới 15 từ) để người đọc tìm lại được.

---

## 3. Quy trình

### Bước 1 — Lập chỉ mục scenario

Đọc toàn bộ scenario và ghi nhận:

- Các section hiện có / thiếu so với template (§1 概要 → §11 Bảng test case)
- Danh sách TC: STT, テスト機能, テスト内容, 正常／準正常, 判定
- Các khu vực trong §2.2, API trong §3, rule trong §4, điều kiện trong §5, 前提条件 chung trong §9

### Bước 2 — Trích xuất requirement và design

- Tách requirement thành các mục kiểm chứng được, mỗi mục một ý, đánh `REQ-01…`. Phân loại: hiển thị, thao tác, validation, enable/disable, quyền/flag, API, lỗi, pagination, chuyển trạng thái.
- Với design, liệt kê từng phần tử UI thành `DSN-01…`: tab, vùng, label, input, giá trị mặc định, placeholder, dấu bắt buộc, button, cột bảng (tên và thứ tự), message, icon (copy, download, delete), phân trang.
- Nếu requirement và design mâu thuẫn nhau → ghi nhận là **要確認**, không tự chọn bên nào đúng.

### Bước 3 — Lập ma trận traceability

Map mỗi `REQ`/`DSN` sang các `TC#` cover nó. Đánh giá:

- ✅ Đủ: có case 正常 và (nếu áp dụng) 準正常/boundary
- ⚠️ Thiếu một phần: chỉ có 正常, thiếu boundary hoặc thiếu nhánh điều kiện
- ❌ Không có case nào

### Bước 4 — Review theo checklist

Đi lần lượt các nhóm A → E bên dưới. Chỉ báo phát hiện có căn cứ; nếu chỉ là đề xuất cải thiện không có căn cứ trong requirement thì phân loại mức **Thấp** hoặc **要確認**.

### Bước 5 — Viết output

Theo đúng mục 6 "Format output", phân mức theo mục 5.

---

## 4. Checklist review

### A. Format theo template

- Có đủ các section: 概要, 項目書作成方針 (対象画面, 確認対象領域, 対応方針), 表示データの取得元, データが存在しない場合, 非表示条件, テスト件数, 担当者, 試験環境, 前提条件, 判定ステータス凡例, bảng test case.
- Bảng test case có đủ 11 cột đúng tên và thứ tự (`TPL §11.1`).
- `テスト内容詳細` của mỗi TC có đủ: 前提条件, các bước thao tác đánh số, điểm cần kiểm tra.
- `正常／準正常` được điền ở mọi TC.
- `判定` chỉ nhận OK / NG / 保留 / NT; TC có 保留 hoặc NT phải có lý do ở cột `不具合チケットNo、理由等`; TC có NG phải có số ticket.
- TC có 判定 nhưng thiếu 実施日, 担当 hoặc 証跡.
- STT liên tục, không trùng, không nhảy số.
- §6 テスト件数: 総数 khớp số dòng thực tế; OK + NG (+ 保留 + NT) khớp số TC đã có 判定.
- §7 có đủ 作成者 và 項目書レビュワー.
- §8 試験環境 có URL, PGID, user, cách lấy credential, tag/config service. Nếu password ghi plaintext → báo mức Trung bình (rủi ro bảo mật), đề xuất ghi cách lấy credential.

### B. Nhất quán nội bộ

- Mỗi khu vực trong §2.2 có ít nhất một TC.
- Mỗi API trong §3 xuất hiện trong ít nhất một TC thành công và một TC lỗi.
- Mỗi field hiển thị liệt kê ở §3 được kiểm tra trong TC hiển thị.
- Mỗi rule ở §4 có TC 準正常 tương ứng.
- Mỗi điều kiện ở §5 có TC cho cả hai nhánh (hiển thị / không hiển thị; enable / disable).
- 前提条件 chung (§9) và 前提条件 từng TC không mâu thuẫn (ví dụ §9 ghi file tối đa 20MB nhưng TC dùng 25MB làm case 正常).
- Tên màn hình, tab, button, field, message dùng thống nhất giữa các section và giữa các TC.
- 期待結果 không mâu thuẫn giữa các TC cùng điều kiện.

### C. Coverage so với requirement

- Mỗi `REQ` có ít nhất một TC; REQ quan trọng có cả 正常 và 準正常.
- **Boundary value** cho mọi giới hạn số: đúng ngưỡng, ngưỡng +1, ngưỡng −1, 0/rỗng. Ví dụ: file 20MB / 20MB + 1 byte / 0 byte; khoảng ngày 90 / 91 ngày; ngày bắt đầu > ngày kết thúc; chỉ nhập một đầu.
- **Validation**: định dạng sai, rỗng, ký tự đặc biệt, nội dung message hiển thị đúng chữ trong requirement.
- **Enable/disable**: từng button × từng trạng thái (chưa chọn file, đã chọn, đang xử lý, trạng thái dữ liệu, quyền).
- **Quyền / flag / cấu hình**: flag true / false / không trả về; user không có quyền; shop không đủ điều kiện.
- **API lỗi**: lỗi 4xx/5xx, timeout, response rỗng, không lấy được URL; kiểm tra màn hình không giữ hoặc cập nhật kết quả sai sau lỗi.
- **Hiển thị ban đầu**: giá trị mặc định của điều kiện tìm kiếm, thứ tự sắp xếp, trạng thái khi chưa có dữ liệu.
- **Pagination**: trang đầu, trang cuối, đổi page_size, reset page_token khi tìm kiếm mới / đổi số dòng / sau khi xóa.
- **Chuyển trạng thái sau thao tác**: sau upload danh sách có refresh không; sau delete bản ghi biến mất và tổng số cập nhật; hủy ở dialog xác nhận.
- **Thao tác lặp**: double click, upload liên tiếp, xóa bản ghi đã bị xóa (chỉ đề xuất nếu requirement có liên quan).
- Các bước 手順 và 期待結果 phải khớp nội dung requirement (giá trị, message, điều kiện).

### D. Đối chiếu design (nếu có)

- Mỗi `DSN` có TC kiểm tra hiển thị.
- Label, thứ tự cột, giá trị mặc định, placeholder, dấu bắt buộc, định dạng ngày/số khớp design.
- Tên button / message trong TC khớp design.
- Phần tử có trên design nhưng requirement không nhắc → 要確認.
- Phần tử có trong TC nhưng không có trên design và requirement → báo "Không có căn cứ".

### E. Chất lượng từng test case

- 期待結果 kiểm chứng được, cụ thể. Không chấp nhận "hiển thị đúng", "hoạt động bình thường", "theo spec" mà không nói rõ là gì.
- Mỗi TC một viewpoint; TC gộp quá nhiều điểm kiểm tra → đề xuất tách.
- 手順 tái hiện được: có dữ liệu test cụ thể (tên file, kích thước, ngày, trạng thái bản ghi).
- Phân loại 正常／準正常 đúng bản chất (case lỗi/validation là 準正常).
- TC trùng lặp nội dung với TC khác.
- テスト機能 / テスト内容 đặt tên rõ, nhất quán.

---

## 5. Mức độ và loại phát hiện

| Mức | Khi nào dùng |
|---|---|
| Cao | Sai so với requirement/design; REQ quan trọng không có case; 期待結果 sai |
| Trung bình | Thiếu 準正常/boundary; mâu thuẫn nội bộ; 期待結果 mơ hồ; rủi ro bảo mật trong 試験環境 |
| Thấp | Format, đặt tên, chính tả, STT, cột trống không ảnh hưởng nội dung |
| 要確認 | Requirement không rõ hoặc mâu thuẫn với design; cần hỏi BA/PO |

Loại phát hiện: `Sai`, `Thiếu case`, `Thiếu boundary`, `Mâu thuẫn`, `Mơ hồ`, `Format`, `Trùng lặp`, `Không có căn cứ`, `要確認`.

---

## 6. Format output

Quy tắc trình bày:

- **Mỗi phát hiện là một mục riêng**, gồm theo thứ tự: tiêu đề → table dọc 2 cột → Giải thích → Đề xuất. Không làm bảng tổng hợp tất cả phát hiện rồi tách chi tiết ở phần khác.
- Table của phát hiện là **table dọc**: cột trái là tên hạng mục, cột phải là nội dung ngắn (một ý, dưới khoảng 20 từ).
- **Giải thích và đề xuất** viết ngay dưới table của phát hiện đó, dạng đoạn văn/bullet, không đưa vào table.
- Ngăn cách các phát hiện bằng `---`.
- Ngôn ngữ output theo ngôn ngữ người dùng (mặc định tiếng Việt). Giữ nguyên thuật ngữ tiếng Nhật như trong scenario (期待結果, 準正常, 洗替登録…).
- Không chép lại nguyên văn đoạn dài của requirement; trích ngắn hoặc dẫn vị trí.
- Sắp xếp phát hiện theo mức: Cao → Trung bình → 要確認 → Thấp. Đánh số F-01, F-02… theo thứ tự đó.
- Phát hiện mức Thấp có thể bỏ phần Giải thích nếu dòng "Vấn đề" đã đủ rõ, nhưng vẫn phải có Đề xuất.
- Nhiều phát hiện cùng gốc (ví dụ thiếu message lỗi ở nhiều TC) → gộp thành một mục, liệt kê tất cả vị trí trong dòng "Vị trí scenario".

Dùng đúng khung sau:

````markdown
# Kết quả review: [Tên 項目書]

## 1. Tóm tắt

| Hạng mục | Giá trị |
|---|---|
| Scenario | [Tên / file], [n] TC |
| Requirement | [Tên / file] hoặc "Không có" |
| Design | [n ảnh] hoặc "Không có" |
| Số REQ / DSN trích xuất | REQ: [n] · DSN: [n] |
| Coverage | ✅ [a] · ⚠️ [b] · ❌ [c] |
| Phát hiện | Cao [x] · TB [y] · 要確認 [z] · Thấp [w] |
| Kết luận | Đạt / Đạt có điều kiện / Cần sửa |

[1–3 câu nhận xét tổng quan, và giới hạn của lần review nếu có (ví dụ: không có design).]

## 2. Phát hiện

### F-01 · [Cao] Thiếu boundary dung lượng file

| Hạng mục | Nội dung |
|---|---|
| Mức | Cao |
| Loại | Thiếu boundary |
| Vị trí scenario | Sau TC#15 (nhóm upload validation) |
| Tham chiếu | REQ-04 · Req §3.2 "tối đa 20MB" |
| Vấn đề | Chưa có case file đúng 20MB và 20MB + 1 byte |

**Giải thích:** [Vì sao đây là vấn đề, rủi ro bỏ sót bug gì, dẫn REQ/DSN/TC liên quan.]

**Đề xuất:** [Sửa gì, chèn ở đâu.] Nếu cần thêm case, viết theo mẫu template:

> **テスト機能:** …
> **テスト内容:** …
> **前提条件:**
> - …
> **手順:**
> 1. …
> **期待結果:**
> - …
> **正常／準正常:** 準正常

---

### F-02 · [Trung bình] 総数 không khớp số dòng thực tế

| Hạng mục | Nội dung |
|---|---|
| Mức | Trung bình |
| Loại | Mâu thuẫn |
| Vị trí scenario | §6 テスト件数 ↔ §11 bảng test case |
| Tham chiếu | TPL §6 |
| Vấn đề | 総数 ghi 66, bảng thực tế có 64 dòng |

**Giải thích:** …

**Đề xuất:** …

---

### F-03 · [Thấp] NT không ghi lý do

| Hạng mục | Nội dung |
|---|---|
| Mức | Thấp |
| Loại | Format |
| Vị trí scenario | TC#22/判定, TC#31/判定 |
| Tham chiếu | TPL §10 |
| Vấn đề | 判定 = NT nhưng cột 理由等 để trống |

**Đề xuất:** Ghi lý do NT vào cột `不具合チケットNo、[保留][NT]理由等`.

## 3. Coverage requirement

Liệt kê từng REQ/DSN một dòng, không dùng table:

- ✅ **REQ-01** Ẩn tab khi isShowTabFlag = false → TC#1, TC#2
- ⚠️ **REQ-04** Giới hạn file 20MB → TC#14 · thiếu boundary, xem **F-01**
- ❌ **REQ-09** Message khi API download lỗi → chưa có TC, xem **F-05**
- ✅ **DSN-03** Icon copy ở cột ファイルID (Ảnh 2) → TC#40

Mọi REQ/DSN ⚠️ hoặc ❌ phải trỏ tới một F-xx ở mục 2.

## 4. Câu hỏi cần xác nhận

1. [REQ-07 / DSN-05] … (câu hỏi ngắn gửi BA/PO, trỏ tới F-xx nếu có)
````

---

## 7. Nguyên tắc

- Không bịa requirement. Điều gì requirement không nói thì là 要確認 hoặc đề xuất mức Thấp, không phải lỗi.
- Mỗi phát hiện bắt buộc có dòng **Vị trí scenario** và **Tham chiếu** trong table của nó. Nếu không có tham chiếu requirement thì ghi `TPL §x` hoặc `Nội bộ (§a ↔ §b)`.
- Không sửa trực tiếp scenario của người dùng trừ khi được yêu cầu; chỉ đề xuất.
- Không đánh giá 判定 thực tế (OK/NG của việc chạy test), chỉ đánh giá chất lượng scenario.
- Ưu tiên phát hiện có giá trị; không liệt kê lặp cùng một lỗi cho từng TC nếu có thể gộp.
