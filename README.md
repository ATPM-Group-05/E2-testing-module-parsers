# End-to-End Testing cho Module Parsers của Authentication Gateway

Dự án nghiên cứu và triển khai kiểm thử an toàn toàn diện cho module phân tích gói tin (parser) của Authentication Gateway trong học phần **An toàn phần mềm - K17 CNTT Phenikaa University**.

Nội dung đề tài tập trung vào 3 trọng tâm kỹ thuật:
1. **Phân tích tham số Gateway Auth**: Phân tích chi tiết số lượng tham số tham gia -> Tính tổ hợp xác định các tham số chính -> Đưa ra không gian trạng thái -> Thiết lập hệ thống ràng buộc.
2. **Mô hình hóa Cấu trúc Kripke**: Xây dựng cấu trúc Kripke chính quy $M = (S, S_0, R, L, AP)$ cho toàn bộ các chuyển đổi trạng thái và kiểm chứng mô hình hình thức BMC (Bounded Model Checking) với Z3 SMT Solver.
3. **Chu trình kiểm thử**: **Sinh mã** $\rightarrow$ **Kiểm thử tĩnh** $\rightarrow$ **Kiểm thử động**.

---

## 1. Phân Tích Tham Số và Tính Tổ Hợp (Gateway Auth)

### 1.1. Bảng tham số đầu vào của Parser
| Ký hiệu | Tên tham số | Kiểu dữ liệu | Ý nghĩa | Phân hoạch tương đương |
| :--- | :--- | :--- | :--- | :--- |
| **P1** | `raw_packet_len` | `int` | Độ dài gói tin thô ($L$) | $L < 6$, $6 \le L < 38$, $L \ge 38$ |
| **P2** | `magic_header` | `bytes[4]` | Định danh giao thức ($M$) | $M = \text{b"PASS"}$, $M \ne \text{b"PASS"}$ |
| **P3** | `payload_len` | `uint16` | Chiều dài tải khai báo ($N$) | $N \le 128$, $128 < N \le 16382$, $N \ge 16383$ |
| **P4** | `token` | `bytes[32]` | Chuỗi token xác thực ($T$) | VALID (`SECRET_TOKEN_2026`), BYPASS (`DEBUG_BYPASS_999`), INVALID |
| **P5** | `payload_data` | `bytes` | Dữ liệu tải thực tế ($D$) | Thiếu hụt ($L < 38 + N$), Đầy đủ ($L \ge 38 + N$) |
| **P6** | `calculated_offset`| `uint32` | Offset con trỏ bộ nhớ | $6 + 4N$ (Lệch mod 4) vs $8 + 4N$ (Căn chỉnh 4 bytes) |
| **P7** | `is_authenticated`| `bool` | Cờ trạng thái nội bộ | `True`, `False` |

### 1.2. Tính toán tổ hợp và xác định các tham số chính
- **Bùng nổ tổ hợp mức bit**: Với chiều dài $L$, không gian bit thô là $2^{8L}$, không thể duyệt cạn.
- **Phân hoạch tương đương (Equivalence Partitioning) & Phân tích giá trị biên (BVA)**:
  - $P_1$ (Độ dài gói): 3 phân hoạch.
  - $P_2$ (Magic Header): 2 phân hoạch.
  - $P_3$ (Payload Length): 3 phân hoạch.
  - $P_4$ (Token): 3 phân hoạch.
  - Không gian tổ hợp tương đương ban đầu: $3 \times 2 \times 3 \times 3 = 54$ tổ hợp.
- **Rút gọn tổ hợp (Combinatorial Reduction)**:
  - Áp dụng các điều kiện bảo vệ (Guard Conditions) theo thứ tự thực thi của Parser:
    - Khi $L < 6$: Parser từ chối ngay lập tức sang trạng thái `BLOCKED`, không phụ thuộc vào $P_2, P_3, P_4$.
    - Khi $M \ne \text{b"PASS"}$: Parser từ chối ngay lập tức sang `BLOCKED`, loại bỏ phụ thuộc $P_3, P_4$.
  - Xác định 4 tham số chính tác động trực tiếp tới sự chuyển đổi trạng thái: $(P_{len\_valid}, P_{magic\_valid}, P_{token\_type}, P_{buffer\_safe})$.

### 1.3. Không gian trạng thái hữu hạn (7 trạng thái)
1. **$S_0$ (`IDLE`)**: Trạng thái khởi tạo, sẵn sàng nhận gói tin.
2. **$S_1$ (`PARSING_HEADER`)**: Phân tích trường Magic và độ dài dữ liệu khai báo.
3. **$S_2$ (`AUTHENTICATING`)**: Kiểm tra và xác thực Token.
4. **$S_3$ (`PROCESSING_PAYLOAD`)**: Kiểm tra biên bộ đệm và trích xuất dữ liệu tải.
5. **$S_4$ (`GRANTED`)**: Cấp quyền truy cập thành công (Success Sink).
6. **$S_5$ (`BLOCKED`)**: Từ chối an toàn khi phát hiện sai phạm hoặc dị dạng (Safe Sink).
7. **$S_6$ (`CRASH_ERROR`)**: Trạng thái lỗi nghiêm trọng / Tràn bộ nhớ (Failure Sink).

### 1.4. Hệ thống ràng buộc (Constraints)
- **Preconditions**:
  - $S_0 \rightarrow S_1 \iff L \ge 6$.
- **Transition Guards**:
  - $S_1 \rightarrow S_2 \iff M = \text{b"PASS"} \land L \ge 38$.
  - $S_2 \rightarrow S_3 \iff T = \text{"SECRET\_TOKEN\_2026"}$.
  - $S_3 \rightarrow S_4 \iff N \le 128 \land L \ge 38 + N$.
- **Safety Invariants**:
  - $\text{Inv}_1$: $AG(State = S_4 \implies T = \text{"SECRET\_TOKEN\_2026"})$.
  - $\text{Inv}_2$: $AG(State = S_3 \lor State = S_4 \implies N \le 128)$.
  - $\text{Inv}_3$: $AG(State \ne S_6)$ (Không tồn tại đường dẫn dẫn tới Crash).
  - $\text{Inv}_4$: $\forall N \in \mathbb{N}: (calculated\_offset \pmod 4 = 0)$.

---

## 2. Cấu Trúc Kripke và Kiểm Chứng Mô Hình BMC

### 2.1. Định nghĩa hình thức Cấu trúc Kripke $M = (S, S_0, R, L, AP)$
- $S = \{S_0, S_1, S_2, S_3, S_4, S_5, S_6\}$.
- $S_0 = \{S_0\}$.
- $AP = \{is\_idle, hdr\_ok, hdr\_fail, tok\_ok, tok\_bypass, tok\_fail, buf\_ok, buf\_overflow, is\_granted, is\_blocked, is\_crash\}$.
- $L: S \rightarrow 2^{AP}$.
- $R \subseteq S \times S$: Quan hệ toàn phần, các trạng thái sink $S_4, S_5, S_6$ đều có self-loop $(s,s) \in R$.

### 2.2. Ma trận chuyển đổi trạng thái Kripke
| Nguồn ($s$) | $S_0$ | $S_1$ | $S_2$ | $S_3$ | $S_4$ | $S_5$ | $S_6$ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **$S_0$: IDLE** | 0 | 1 | 0 | 0 | 0 | 1 | 0 |
| **$S_1$: PARSING_HEADER** | 0 | 0 | 1 | 0 | 1* | 1 | 0 |
| **$S_2$: AUTHENTICATING** | 0 | 0 | 0 | 1 | 0 | 1 | 0 |
| **$S_3$: PROCESSING_PAYLOAD** | 0 | 0 | 0 | 0 | 1 | 1 | 1* |
| **$S_4$: GRANTED (Sink)** | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| **$S_5$: BLOCKED (Sink)** | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| **$S_6$: CRASH_ERROR (Sink)** | 0 | 0 | 0 | 0 | 0 | 0 | 1 |

*Ghi chú*: `1*` là các chuyển đổi chứa lỗ hổng an toàn trên mã lỗi ($S_1 \rightarrow S_4$ qua backdoor và $S_3 \rightarrow S_6$ qua tràn buffer).

### 2.3. Bounded Model Checking (BMC) với Z3 SMT Solver
- **$K = 2$**: Z3 phát hiện Counterexample vi phạm bất biến xác thực ($S_0 \rightarrow S_1 \rightarrow S_4$ thông qua token `DEBUG_BYPASS_999`).
- **$K = 4$**: Z3 phát hiện Counterexample vi phạm an toàn bộ nhớ ($S_0 \rightarrow S_1 \rightarrow S_2 \rightarrow S_3 \rightarrow S_6$ với $N > 128$).

---

## 3. Quy Trình 3 Giai Đoạn

### Giai đoạn 1: Sinh mã (Code Generation) - `step2_codegen.py`
- Tự động sinh mã nguồn Gateway an toàn (`generated_gateway.py`):
  - Kiểm tra độ dài $\ge 38$ ngay tại header guard.
  - Kiểm tra biên $N \le 128$ trước khi xử lý tải, chặn mọi nguy cơ `MemoryError`.
  - Triệt tiêu cửa sau `DEBUG_BYPASS_999`.
  - Căn chỉnh bộ nhớ: Bổ sung 2 bytes padding thành $Offset = 8 + 4N$, đảm bảo $Offset \pmod 4 = 0$.
- Tự động sinh bộ ca kiểm thử chuyển đổi trạng thái Kripke (`test_cases.json`): 13 ca kiểm thử phủ kín 100% các nhánh chuyển đổi.

### Giai đoạn 2: Kiểm thử tĩnh (Static Testing) - `step3_static_testing.py`
- **Phân tích AST**:
  - Phát hiện `HARDCODED_BACKDOOR`, `MISALIGNED_OFFSET_CALC`, `MISSING_EARLY_BOUNDS_CHECK`, `INSUFFICIENT_LENGTH_GUARD`.
  - Xác nhận bản sinh mã đạt chuẩn an toàn 100%.
- **Kiểm chứng SMT bằng Z3 Solver**:
  - Integer Overflow: Target `SAT` vs Generated `UNSAT` (chứng minh an toàn tuyệt đối).
  - Memory Alignment: Target vi phạm dư 2 vs Generated `UNSAT` (chia hết cho 4).
  - Buffer Overflow: Target `SAT` vs Generated `UNSAT`.
  - Auth Invariant: Target `SAT` vs Generated `UNSAT`.

### Giai đoạn 3: Kiểm thử động (Dynamic Testing) - `step4_dynamic_testing.py`
- **Kiểm thử bộ test Kripke**:
  - Độ bao phủ 13/13 ca kiểm thử (100.0% PASS trên Generated Gateway).
- **Kiểm thử Fuzzing động (10,000 iterations)**:
  - So sánh Black-box vs White-box (nhận thức cấu trúc và biên tham số).
  - Kết quả trên Target Gateway: White-box phát hiện 1,443 lần Crash (ngay từ lần lặp thứ 3) và 2,649 lần Bypass (ngay từ lần lặp thứ 2).
  - Kết quả trên Generated Gateway: 0 lần Crash, 0 lần Bypass, 100% từ chối an toàn.

---

## 4. Hướng Dẫn Chạy Toàn Bộ Dự Án

### Cài đặt thư viện:
```bash
pip install -r requirements.txt
```

### Chạy toàn bộ chu trình tích hợp:
```bash
python main.py
```

### Chạy từng giai đoạn độc lập:
```bash
# Phân tích tham số, cấu trúc Kripke & BMC Z3
python step1_kripke_analysis.py

# Sinh mã Gateway an toàn và sinh test suite Kripke
python step2_codegen.py

# Kiểm thử tĩnh (AST & Formal SMT Verification)
python step3_static_testing.py

# Kiểm thử động (Kripke Test Suite & Fuzzing 10,000 iterations)
python step4_dynamic_testing.py
```