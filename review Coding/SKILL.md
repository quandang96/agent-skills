---
name: "mr-code-review"
description: "Review code change của merge request trên GitLab web (Vue3/Nuxt4/GraphQL, BFF Node gRPC, Go gRPC), đối chiếu requirement markdown nếu có, báo bug theo file và dòng."
---

# Review code Merge Request (GitLab web)

Skill dùng khi người dùng yêu cầu review một MR trên GitLab: kiểm tra code change có bug không, có đúng requirement không, có sai convention không.

Ngôn ngữ báo cáo: **tiếng Việt** (giữ nguyên tên kỹ thuật, tên hàm, tên file).

## Stack dự án

| Thành phần | Công nghệ |
|---|---|
| `web_front` | Vue 3, vue-facing-decorator (class component), Nuxt 4, GraphQL client |
| `web_bff` | Node.js (TypeScript), GraphQL server, gRPC client |
| Các service khác | Go, gRPC (protobuf) |

## Input

1. **MR trên GitLab web** (bắt buộc): đọc trực tiếp nội dung tab **Changes** của MR đang mở (hoặc link MR người dùng cung cấp). Không cần và không dùng lệnh `git`/CLI.
   - Đọc thêm tiêu đề, description, target branch của MR để hiểu mục đích.
   - Nếu MR nhiều file và GitLab thu gọn (collapsed) một số file lớn, liệt kê các file chưa đọc được thay vì bỏ qua âm thầm.
2. **Requirement markdown** (tuỳ chọn): nội dung `.md` mô tả yêu cầu / spec / ticket, dán vào chat hoặc đính kèm. Có thì bắt buộc đối chiếu (bước 3).
3. Ghi chú thêm của người dùng (phạm vi, phần cần tập trung).

Nếu không đọc được nội dung Changes thì báo rõ và hỏi lại, không đoán nội dung code.

## Quy trình

### Bước 1 — Nắm danh sách thay đổi
- Lấy danh sách file từ cây file trong tab Changes.
- Phân loại theo tầng: front (`*.vue`, `*.ts` trong `web_front`, `*.graphql`/`*.gql` của client), bff (resolver, schema, gRPC client), service Go (`*.go`), contract (`*.proto`, schema GraphQL), config/migration/test.
- Bỏ qua file sinh tự động (`*.pb.go`, `*_grpc.pb.go`, codegen GraphQL types, lockfile) trừ khi thay đổi bất thường.

### Bước 2 — Đọc ngữ cảnh
- Đọc cả các dòng context (không đổi) quanh mỗi hunk để hiểu hàm/component bao quanh. Nếu cần thêm, xem file đầy đủ qua "View file @ <commit>" hoặc mở rộng (expand) vùng code bị ẩn trong diff.
- Truy vết luồng end-to-end khi MR chạm nhiều tầng: component Vue → query/mutation GraphQL → resolver BFF → gRPC call → handler Go → DB. Kiểm tra tên field, kiểu, nullability khớp xuyên suốt.
- Convention: ưu tiên convention của chính repo (thể hiện trong code lân cận cùng loại, các file cấu hình lint nếu có trong MR) hơn convention chung.
- Phần nào không nhìn thấy được từ MR (code ngoài diff, service khác) thì không khẳng định — ghi mức **Cần xác nhận**.

### Bước 3 — Đối chiếu requirement (nếu có)
- Tách requirement thành từng mục kiểm chứng được (R1, R2, ...): chức năng, validate, phân quyền, message, điều kiện biên, hiển thị.
- Mỗi mục xác định: **Đã đáp ứng** / **Thiếu** / **Sai lệch** / **Không xác định được từ MR**, kèm vị trí code chứng minh.
- Ghi nhận cả code làm **thừa** so với requirement.

### Bước 4 — Review theo checklist (mục dưới)
Chỉ báo vấn đề nằm trên dòng thay đổi hoặc bị ảnh hưởng trực tiếp bởi thay đổi. Vấn đề có sẵn không liên quan thì gom vào mục "Ghi chú ngoài phạm vi" (tối đa vài dòng).

### Bước 5 — Xác định vị trí chính xác
- File: đường dẫn đầy đủ như hiển thị trên header của file trong tab Changes.
- Dòng: lấy theo **cột số dòng mới (bên phải)** trong diff của GitLab — đây là số dòng người review có thể click để comment.
- Với dòng bị xoá (chỉ có số ở cột cũ): ghi `(đã xoá) L<số cũ>`.
- Vấn đề trải nhiều dòng: ghi khoảng `23–25`.
- Không bịa số dòng. Không chắc số dòng thì ghi tên hàm/method làm vị trí và đánh dấu `~`.

### Bước 6 — Viết báo cáo theo format bên dưới.

## Checklist theo stack

### web_front — Vue 3 + vue-facing-decorator + Nuxt 4
**vue-facing-decorator / class component**
- Class có `@Component` và `extends Vue` (hoặc `toNative` khi export nếu dự án dùng).
- Field data phải được khởi tạo giá trị (kể cả `null`); field chỉ khai báo kiểu, không gán giá trị có thể không reactive.
- `@Prop`: có kiểu, `required`/`default`; default của object/array phải là factory function. Không mutate prop trực tiếp — dùng emit / `@Model` / bản sao local.
- `@Watch`: đúng tên property, cân nhắc `deep`/`immediate`; tránh watcher gây vòng lặp cập nhật.
- `@Emit`/`$emit`: tên event khớp với nơi lắng nghe ở component cha.
- Getter làm computed không được có side effect, không async.
- Lifecycle hook đúng tên Vue 3 (`beforeUnmount`/`unmounted`, không dùng `beforeDestroy`/`destroyed`). Không trộn Composition API trong class trừ khi dự án cho phép (`setup()` hook).
- Listener, interval, observer, subscription tạo trong `mounted` phải được huỷ ở `beforeUnmount`.
- `this` trong callback có đúng ngữ cảnh.

**Nuxt 4 / SSR**
- Truy cập `window`, `document`, `localStorage`, `navigator` ngoài `mounted` hoặc không có guard `import.meta.client` → lỗi SSR (Nuxt 4 dùng `import.meta.client`/`import.meta.server`, không dùng `process.client`).
- Hydration mismatch: render phụ thuộc thời gian thực, random, timezone, dữ liệu chỉ có ở client.
- State module-level (biến global ngoài component/store) bị chia sẻ giữa các request trên server → rò rỉ dữ liệu giữa user. Dùng `useState`/Pinia.
- `useAsyncData`/`useFetch`: key duy nhất, xử lý `error`/`pending`, không fetch trùng ở cả server và client.
- `runtimeConfig`: secret không được nằm trong `public`.
- Cấu trúc thư mục Nuxt 4 (`app/`), middleware (`defineNuxtRouteMiddleware`), `navigateTo` phải được `return`.

**Template**
- `v-for` thiếu `:key` hoặc key là index với list có thể đổi thứ tự; `v-if` cùng phần tử với `v-for`.
- `v-html` với dữ liệu người dùng → XSS.
- Optional chaining cho dữ liệu có thể null từ API; có trạng thái loading/empty/error.
- Text hard-code nếu dự án dùng i18n.

**GraphQL client**
- Field trong query khớp schema (nếu schema có trong MR), đúng kiểu và nullability; biến đúng kiểu (`ID!`, `Int`...).
- Xử lý `errors` (kể cả partial data), loading state.
- Sau mutation: cập nhật cache / refetch query liên quan.
- `fetchPolicy` phù hợp; không lấy field thừa; dùng fragment theo convention.
- Query đổi nhưng type codegen không được cập nhật trong MR.

### web_bff — Node.js + GraphQL + gRPC
- Resolver gọi gRPC trong vòng lặp / field resolver per-item → N+1; dùng DataLoader / batch API.
- `async` thiếu `await`, promise không được xử lý, `forEach` với async callback, `Promise.all` khi cần partial result.
- gRPC: luôn đặt **deadline/timeout**; propagate metadata (auth token, trace/request id, locale); không tạo client mới mỗi request.
- Map gRPC status → GraphQL error đúng (NOT_FOUND, INVALID_ARGUMENT, PERMISSION_DENIED, UNAUTHENTICATED); không lộ stack trace / message nội bộ.
- Proto3 zero value vs null: chuỗi rỗng / 0 / false không phân biệt được với "không có" — kiểm tra mapping sang field GraphQL nullable.
- `int64`/`uint64` (Long/string) → số JS mất chính xác; enum proto ↔ enum GraphQL map đủ giá trị, xử lý `UNSPECIFIED`.
- Timestamp proto ↔ ISO string, timezone.
- Authorization cho mọi field/resolver mới; không tin input từ client (user id, role).
- Validate input (độ dài, phạm vi, `limit` phân trang tối đa).
- Schema GraphQL: breaking change (xoá field, đổi kiểu, đổi nullability) làm vỡ front.
- Log không chứa PII / token.

### Service Go + gRPC
- Lỗi bị bỏ qua (`_ =`, không check `err`); error không wrap ngữ cảnh (`fmt.Errorf("...: %w", err)`); dùng `errors.Is/As` thay vì so sánh chuỗi.
- Trả `status.Error(codes.X, ...)` đúng mã; không trả `Unknown`/`Internal` cho lỗi validate.
- Nil pointer: truy cập field message proto lồng nhau trực tiếp thay vì getter `GetX()`; map nil; con trỏ trả về khi not found.
- `context`: truyền ctx xuống DB/gRPC/HTTP, không dùng `context.Background()` trong handler.
- Goroutine leak, thiếu `WaitGroup`/`errgroup`, data race trên map/slice dùng chung, copy mutex theo value.
- `defer` trong vòng lặp; quên `rows.Close()`, `rows.Err()`, `resp.Body.Close()`.
- Transaction thiếu rollback khi lỗi, không check lỗi commit.
- SQL nối chuỗi → injection; query mới thiếu index; N+1 query.
- Ép kiểu số tràn (int64 → int32), so sánh time khác timezone.
- Validate request ở đầu handler.
- Convention: tên exported có doc comment, receiver name nhất quán, không panic trong code thường, theo style code lân cận.

### Contract (`.proto`, schema GraphQL)
- Không đổi số field / kiểu field đã dùng; field xoá phải `reserved` số và tên.
- Thêm field mới: BFF và front có cập nhật mapping tương ứng (nếu nằm trong MR); generated code đã regenerate.
- Đổi tên RPC/service/package → client cũ vỡ.

### Chung
- Điều kiện biên: off-by-one, `<` vs `<=`, mảng rỗng, chuỗi rỗng, null, trang cuối phân trang.
- Copy-paste sai biến, điều kiện đảo ngược, return sớm bỏ sót cleanup.
- Hard-code giá trị (URL, ID, magic number) nên đưa vào config/const.
- Code chết, `console.log`/`fmt.Println` debug, TODO chưa xử lý, code comment thừa.
- Thiếu test cho logic mới / test không còn đúng.

## Mức độ

| Mức | Ý nghĩa |
|---|---|
| 🔴 Critical | Sai dữ liệu, crash, lỗ hổng bảo mật, rò dữ liệu, breaking contract |
| 🟠 Major | Bug chức năng, sai/thiếu requirement, lỗi ở trường hợp biên phổ biến |
| 🟡 Minor | Chưa hợp lý, hiệu năng, khó bảo trì, thiếu xử lý lỗi ít gặp |
| 🔵 Convention | Sai convention / style |
| ⚪ Cần xác nhận | Nghi ngờ, cần xem code ngoài MR hoặc thông tin thêm để kết luận |

Loại: `Bug`, `Requirement`, `Bảo mật`, `Hiệu năng`, `SSR`, `Contract`, `Convention`, `Thiết kế`.

## Format báo cáo

Nguyên tắc: **mục ngắn (nội dung bug, file, dòng) dùng table; phần giải thích và giải pháp viết dạng văn bản/code block, KHÔNG đưa vào table.**

```markdown
# Review MR: <tiêu đề MR> (!<số MR>)

**Tóm tắt:** <2–3 câu: MR làm gì, đánh giá chung, có nên merge chưa>
**Thống kê:** 🔴 x · 🟠 x · 🟡 x · 🔵 x · ⚪ x

## 1. Đối chiếu requirement
(Bỏ mục này nếu không có requirement)

| ID | Requirement (tóm tắt) | Trạng thái | Vị trí |
|---|---|---|---|
| R1 | ... | ✅ Đã đáp ứng | `web_front/app/pages/cart.vue:42` |
| R2 | ... | ❌ Thiếu | — |
| R3 | ... | ⚠️ Sai lệch | `web_bff/src/resolvers/order.ts:88` |

## 2. Danh sách vấn đề

| # | Mức | Loại | File | Dòng | Nội dung |
|---|---|---|---|---|---|
| 1 | 🔴 | Bug | `web_bff/src/resolvers/order.ts` | 57 | Không set deadline khi gọi gRPC `GetOrder` |
| 2 | 🟠 | SSR | `web_front/app/pages/cart.vue` | 23–25 | Truy cập `localStorage` trong `created` |

## 3. Chi tiết và đề xuất

### #1 — Không set deadline khi gọi gRPC `GetOrder`
`web_bff/src/resolvers/order.ts:57`

**Giải thích:** <vì sao là lỗi, khi nào xảy ra, hậu quả>

**Đề xuất:**
```ts
// code sửa gợi ý
```

### #2 — ...

## 4. File chưa review được (nếu có)
- <file bị GitLab thu gọn / quá lớn / không đọc được>

## 5. Ghi chú ngoài phạm vi (tuỳ chọn)
- <vấn đề có sẵn, không do MR gây ra>
```

Quy tắc trình bày:
- Cột "Nội dung" trong table tối đa ~1 câu ngắn; mọi lý giải đưa xuống mục 3.
- Sắp xếp theo mức độ (🔴 trước), cùng mức thì theo file.
- Mỗi finding ở mục 3 có tiêu đề trùng số `#` với table, kèm `file:dòng` để người review tìm và comment thẳng trên GitLab.
- Code đề xuất ngắn gọn, đúng style repo; chỉ đưa phần thay đổi.
- Không có vấn đề nào thì ghi rõ "Không phát hiện vấn đề" và vẫn giữ mục đối chiếu requirement.