DD Review and Jira Output
Core rules
Base every conclusion only on the supplied Requirement, confirmed Q&A, Screen Design, and DD.
Do not infer missing business rules. If evidence is insufficient, write: Chưa đủ căn cứ, cần xác nhận.
Use this priority when sources conflict: confirmed Requirement/Q&A, Screen Design, DD, current implementation.
Preserve exact Japanese labels, messages, statuses, field names, and dates when comparing.
Review workflow
Extract rules from Requirement and Design, including display conditions, enable/disable rules, status, validation, messages, dates, API fields, and permissions.
Find the matching DD location: sheet, section, item, cell, or cell range.
Compare exact values and logic, especially AND/OR, < / <=, date boundaries, status combinations, and message wording.
Also check contradictions between DD sheets or sections.
Classify each finding as:
confirmed error: directly contradicts Requirement or Design;
internal inconsistency: DD sections contradict each other;
missing design: Requirement contains a rule that DD does not cover;
needs confirmation: source material is unclear or incomplete.
Never invent a cell address. If the exact cell is unknown, identify the sheet and section only.
Review output
For a detailed review, write:

## [Tên vấn đề]
- *Vị trí DD:* Sheet ..., mục ..., ô/vùng ...
- *Nội dung hiện tại:* ...
- *Vấn đề:* ...
- *Nội dung đúng:* ...
- *Căn cứ:* Requirement/Design mục ...
- *Đề xuất sửa:* ...
Jira output
When the user asks for Jira bugs, output only Title and Description in concise Vietnamese.

## Bug 1

*Title*

```text
[DD] [Đối tượng] [bản chất lỗi]
Description

Tại sheet「[Tên sheet]」, mục「[Tên mục]」, ô/vùng「[Vị trí]」đang ghi hoặc thiết lập [nội dung sai] không đúng với Requirement/Design.

Sửa [nội dung hiện tại] thành [nội dung đúng].

For logic errors, use:

```text
Tại sheet「...」, mục「...」đang thiết lập sai [điều kiện].

Sửa để [điều kiện đúng].
For missing design, use:

Tại sheet「...」, mục「...」chưa mô tả [nội dung thiếu].

Bổ sung [điều kiện hoặc cách xử lý cần thiết] theo Requirement.
Keep descriptions short. Do not add Overview, Actual Result, Expected Result, severity, reproduction steps, or long evidence sections unless requested.