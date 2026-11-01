---
name: dd-review-jira
description: Review a Detail Design (DD / 詳細設計書) against Requirement, confirmed Q&A and Screen Design, then report findings or Jira bugs in Vietnamese. Use when the user asks to review or check a DD, compare DD with requirement/design, find DD errors, or create Jira bugs for DD issues.
---

# DD Review and Jira Output

## Core rules

- Base every conclusion only on the supplied Requirement, confirmed Q&A, Screen Design, and DD.
- Do not infer missing business rules. If evidence is insufficient, write exactly: `Chưa đủ căn cứ, cần xác nhận.`
- When sources conflict, use this priority (highest first):
  1. Confirmed Requirement / Q&A
  2. Screen Design
  3. DD
  4. Current implementation
- Preserve exact Japanese labels, messages, statuses, field names, and dates. Quote them inside「」and never translate or paraphrase them.
- One finding = one issue. Do not merge unrelated issues; do not split one issue into several findings.
- Report only real differences. Do not report formatting or wording preferences unless they change meaning.

## Location rules (bắt buộc)

Every finding must state its DD location in this fixed order:

`Sheet「<tên sheet>」 › Mục「<tên mục/section>」 › Ô/vùng「<địa chỉ>」`

- **Sheet**: exact sheet name as written in the DD.
- **Mục**: section title, item name, or item No. (e.g.「2.3 入力チェック」, item No.15).
- **Ô/vùng**: cell (`C12`) or range (`C12:H15`). If the DD is a table, add the row identifier (e.g. `No.15, cột「条件」`).
- Never invent a cell address. If the exact cell is unknown, write `Chưa xác định ô` and give sheet + section (+ row/item No. if known).
- Apply the same format to the source in **Căn cứ**: `Requirement mục「...」` / `Q&A No.…` / `Screen Design「<màn hình>」, mục「...」`.

## Review workflow

1. **Extract rules** from Requirement, Q&A and Screen Design: display conditions, enable/disable rules, statuses, validations, messages, dates, API fields, permissions, initial values, sort order.
2. **Locate** the matching DD position (sheet › section › cell/range).
3. **Compare** exact values and logic. Check carefully:
   - AND / OR, NOT, parentheses
   - `<` vs `<=`, `>` vs `>=`, date/time boundaries (start/end inclusive?)
   - Status combinations and transitions
   - Message ID and exact message text
   - Field name, type, length, required/optional, format
   - Role / permission conditions
4. **Cross-check DD internally**: contradictions between sheets or sections (e.g. screen item spec vs. processing logic vs. API mapping).
5. **Classify** each finding:
   - `confirmed error`: directly contradicts Requirement or Design
   - `internal inconsistency`: DD sections contradict each other
   - `missing design`: Requirement contains a rule that DD does not cover
   - `needs confirmation`: source material is unclear or incomplete
6. **Self-check** before output: every finding has a location in the fixed format, a source in Căn cứ, and no invented cell or rule.

## Review output

Use this structure for each finding. Short, factual items go in the table; **Vấn đề** and **Đề xuất sửa** are written as prose below the table (not in the table).

Table rules:
- Keep each table cell short (one line, or a few lines with `<br>`).
- If the current or correct content is long (multi-condition logic, long message, several fields), write `Xem bên dưới` in the cell and put the full content in a `text` code block right after the table, labelled **Nội dung hiện tại** / **Nội dung đúng**.

Template:

```markdown
## [Số thứ tự]. [Tên vấn đề] — `[phân loại]`

| Mục | Chi tiết |
|---|---|
| Vị trí DD | Sheet「...」 › Mục「...」 › Ô/vùng「...」 |
| Nội dung hiện tại | ... |
| Nội dung đúng | ... |
| Căn cứ | Requirement mục「...」 / Q&A No.… / Screen Design「...」mục「...」 |

**Vấn đề:** Giải thích ngắn gọn vì sao nội dung hiện tại sai hoặc thiếu, chỉ rõ điểm khác biệt (ví dụ: DD dùng `<` nhưng Requirement yêu cầu `<=`).

**Đề xuất sửa:** Tại Sheet「...」 › Mục「...」 › Ô/vùng「...」, sửa「...」thành「...」.
```

For `needs confirmation`, set **Nội dung đúng** to `Chưa đủ căn cứ, cần xác nhận.` and state in **Đề xuất sửa** what needs to be confirmed and with whom (BA/khách hàng).

When there are 3 or more findings, add a summary table at the top before the details:

```markdown
| No. | Vấn đề | Phân loại | Vị trí DD |
|---|---|---|---|
| 1 | ... | confirmed error | Sheet「...」 › Mục「...」 › 「C12」 |
```

## Jira output

When the user asks for Jira bugs, output only **Title** and **Description** in concise Vietnamese. Use the same fixed location format as above.

```markdown
## Bug [số]

**Title**

```text
[DD] [Đối tượng] [bản chất lỗi]
```

**Description**

```text
Tại sheet「[Tên sheet]」, mục「[Tên mục]」, ô/vùng「[Vị trí]」đang ghi hoặc thiết lập [nội dung sai] không đúng với Requirement/Design.

Sửa [nội dung hiện tại] thành [nội dung đúng].
```
```

For logic errors:

```text
Tại sheet「...」, mục「...」, ô/vùng「...」đang thiết lập sai [điều kiện].

Sửa để [điều kiện đúng].
```

For missing design:

```text
Tại sheet「...」, mục「...」chưa mô tả [nội dung thiếu].

Bổ sung [điều kiện hoặc cách xử lý cần thiết] theo Requirement.
```

Jira rules:
- Title ≤ ~80 characters; [Đối tượng] = screen/item/API name, kept in Japanese if that is how the DD names it.
- If the cell is unknown, write `ô/vùng「Chưa xác định ô」` rather than omitting the location.
- Keep descriptions short. Do not add Overview, Actual Result, Expected Result, severity, reproduction steps, or long evidence sections unless requested.
- Do not create Jira bugs for `needs confirmation` findings; list them separately as questions to confirm.
