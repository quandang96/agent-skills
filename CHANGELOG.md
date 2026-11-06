# Changelog

## 2.1 — 2026-11-06

- Tạo các file mà SKILL.md 2.0 đã tham chiếu nhưng còn thiếu: `references/*.md`, `schemas/finding.schema.json`.
- Thay rule P0–P3 dạng mô tả bằng decision matrix có thứ tự R01–R15, mỗi finding ghi `rule_id`.
- Bổ sung rule cho critical chưa có fix (R03), KEV (R01), EOL của OS/Node.js (R06), finding có scope/applicability chưa rõ (R07).
- Bỏ điều kiện mơ hồ "nhiều vulnerability có thể khai thác" của P1.
- Quyết định CI tổng: thiếu input không được ra `PASS`, nhưng cũng không hạ `BLOCK`.
- Report lệch thời gian không còn bị coi là `DATA_CONFLICT`; dùng `STALE_REPORT`. Khác digest mới là conflict.
- Thuật toán fix target theo nhánh semver, xử lý `0.x`, pre-release và `already_fixed_conflict`; có `scripts/fix_target.py`.
- Chuẩn hóa purl: decode `%40`, bỏ qualifier khỏi khóa ghép; thêm trạng thái `MATCHED_TRIVY_UZOMUZO`.
- Scope cho package có nhiều path; tách trục `dependency_relation` khỏi `scope`.
- Mapping cụ thể cho Trivy native, GitLab Code Quality, container scanning, SARIF và giới hạn của Code Quality.
- Exception: điều kiện hợp lệ, xử lý hết hạn, OpenVEX.
- `findings.json` có `remediation_groups` để một thay đổi đóng nhiều finding.
- Thêm `scripts/normalize_reports.py` để parse, ghép và đối soát số lượng.
- Thêm `evals/cases.md` gồm 18 tình huống kiểm thử.
- Tách phần sửa repository sang skill `dependency-remediation`.

## 2.0

- Tách SKILL.md thành bản ngắn, thêm nguyên tắc chống prompt injection, so sánh version theo ecosystem, input tùy chọn và output `findings.json`.

## 1.0

- Bản đầu tiên, toàn bộ rule trong một file.
