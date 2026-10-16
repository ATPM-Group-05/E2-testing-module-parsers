# Quy Trình Đánh Giá An Toàn End-to-End Cho Module Parsers Của Authentication Gateway

Dự án nghiên cứu và triển khai kiểm thử an toàn toàn diện End-to-End cho module phân tích gói tin (parser) của Authentication Gateway trong môn học An toàn phần mềm.

Đề tài tập trung giải quyết trọn vẹn 3 yêu cầu cốt lõi:
1. **Đặc tả hình thức Gateway Auth**: Phân tích tham số, tính tổ hợp xác định các tham số chính, đặc tả không gian 7 trạng thái và toàn bộ các mệnh đề chuyển đổi trạng thái $\Phi(S_i, S_j)$.
2. **Kiểm chứng hình thức BMC/Z3 & Mô hình phân loại lỗi**: Thiết lập hệ thống ràng buộc an toàn, cơ sở toán học sinh Test Cases từ nghiệm phản chứng (Counterexamples) của Z3 SMT Solver, chuẩn hóa theo mô hình phân loại lỗi CWE.
3. **Kiểm thử động Fuzzing**: Thực nghiệm Bounded Fuzzing (Black-box vs White-box), phát hiện phân loại lỗi Crash và Hang, đo lường độ bao phủ cạnh (Edge Coverage) và số lượng đường đi thực thi độc nhất (Path Tracing).

---

## 1. Đặc Tả Trạng Thái và Mệnh Đề Chuyển Đổi (Gateway Auth)

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

### 1.3. Đặc tả hình thức không gian 7 trạng thái
| Trạng thái | Tên trạng thái | Ý nghĩa ngữ nghĩa | Điều kiện bất biến / Vào | Mệnh đề AP |
| :--- | :--- | :--- | :--- | :--- |
| **$S_0$** | `IDLE` | Khởi tạo, chờ nhận gói tin | $len(raw\_bytes) \ge 0$ | $is\_idle$ |
| **$S_1$** | `PARSING_HEADER` | Đọc Magic 4B và Chiều dài khai báo 2B | $len(raw\_bytes) \ge 6$ | $hdr\_parsed$ |
| **$S_2$** | `AUTHENTICATING` | Xác thực chuỗi Token bảo mật 32B | $M = \text{b"PASS"} \land L \ge 38$ | $tok\_checking$ |
| **$S_3$** | `PROCESSING_PAYLOAD` | Kiểm tra biên bộ đệm và nạp dữ liệu | $T = \text{"SECRET\_TOKEN\_2026"}$ | $buf\_processing$ |
| **$S_4$** | `GRANTED` | Chấp thuận truy cập (Terminal Success) | $is\_authenticated = True$ | $is\_granted$ |
| **$S_5$** | `BLOCKED` | Từ chối an toàn (Terminal Safe Reject) | $Gói\ tin\ sai\ quy\ chuẩn\ \lor\ Token\ sai$ | $is\_blocked$ |
| **$S_6$** | `CRASH_ERROR` | Lỗi sập bộ nhớ (Terminal Panic) | $N > 128$ (Chưa kiểm tra biên) | $is\_crash$ |

### 1.4. Hệ thống ràng buộc (Constraints) & Bất biến an toàn
- **Preconditions**:
  - $S_0 \rightarrow S_1 \iff L \ge 6$.
- **Transition Guards**:
  - $S_1 \rightarrow S_2 \iff M = \text{b"PASS"} \land L \ge 38$.
  - $S_2 \rightarrow S_3 \iff T = \text{"SECRET\_TOKEN\_2026"}$.
  - $S_3 \rightarrow S_4 \iff N \le 128 \land L \ge 38 + N$.
- **Safety Invariants**:
  - $\text{Inv}_1$: $AG(State = S_4 \implies T = \text{"SECRET\_TOKEN\_2026"})$ (Bảo toàn xác thực).
  - $\text{Inv}_2$: $AG(State = S_3 \lor State = S_4 \implies N \le 128)$ (An toàn vùng đệm).
  - $\text{Inv}_3$: $AG(State \ne S_6)$ (Không tồn tại đường dẫn dẫn tới Crash).
  - $\text{Inv}_4$: $\forall N \in \mathbb{N}: (calculated\_offset \pmod 4 = 0)$ (Căn chỉnh bộ nhớ phần cứng).

### 1.5. Đặc tả các mệnh đề chuyển đổi trạng thái (Transition Propositions)
Các mệnh đề logic chuyển trạng thái $\Phi(S_i, S_j)$:
- $\Phi(S_0, S_1) \iff (s = S_0) \land (L \ge 6) \land (s' = S_1)$
- $\Phi(S_0, S_5) \iff (s = S_0) \land (L < 6) \land (s' = S_5)$
- $\Phi(S_1, S_2) \iff (s = S_1) \land (M = \text{'PASS'}) \land (T \ne \text{'DEBUG\_BYPASS\_999'}) \land (s' = S_2)$
- $\Phi(S_1, S_4) \iff (s = S_1) \land (M = \text{'PASS'}) \land (T = \text{'DEBUG\_BYPASS\_999'}) \land (s' = S_4)$ *(Lỗ hổng Backdoor)*
- $\Phi(S_1, S_5) \iff (s = S_1) \land (M \ne \text{'PASS'} \lor L < 38) \land (s' = S_5)$
- $\Phi(S_2, S_3) \iff (s = S_2) \land (T = \text{'SECRET\_TOKEN\_2026'}) \land (s' = S_3)$
- $\Phi(S_2, S_5) \iff (s = S_2) \land (T \ne \text{'SECRET\_TOKEN\_2026'}) \land (s' = S_5)$
- $\Phi(S_3, S_4) \iff (s = S_3) \land (N \le 128) \land (s' = S_4)$
- $\Phi(S_3, S_6) \iff (s = S_3) \land (N > 128) \land (s' = S_6)$ *(Lỗ hổng Buffer Overflow)*
- $\Phi_{sink}(s, s') \iff (s \in \{S_4, S_5, S_6\}) \land (s' = s)$ *(Self-loop bảo toàn quan hệ toàn phần)*

Công thức quan hệ chuyển đổi toàn cục:
$$T(s, s') \iff \bigvee_{i, j} \Phi(S_i, S_j)$$

---

## 2. Cấu Trúc Kripke, BMC và Mô Hình Phân Loại Lỗi

### 2.1. Cấu trúc Kripke chính quy $M = (S, S_0, R, L, AP)$
- $S = \{S_0, S_1, S_2, S_3, S_4, S_5, S_6\}$.
- $S_0 = \{S_0\}$.
- $AP = \{is\_idle, hdr\_parsed, tok\_checking, buf\_processing, is\_granted, is\_blocked, is\_crash\}$.
- $R \subseteq S \times S$: Quan hệ toàn phần, các trạng thái kết thúc $S_4, S_5, S_6$ đều có self-loop $(s,s) \in R$.

### 2.2. Cơ sở toán học sinh Test Case từ BMC / Z3 Solver
Khi giải phủ định của các bất biến an toàn $\neg \text{Invariant}(s_k)$, nếu Z3 Solver trả về `sat`, nghiệm của mô hình $M = \text{Model}(Solver)$ cung cấp trực tiếp vector giá trị đầu vào (Counterexample Valuation). Bộ giá trị này chính là cơ sở toán học khách quan để tổng hợp Test Cases biên:
- **Nghiệm 1 ($K=2$)**: $Token = \text{"DEBUG\_BYPASS\_999"}$ sinh ra `TC_06_BYPASS_TOKEN_ATTACK`.
- **Nghiệm 2 ($K=4$)**: $N = 129, 512 > 128$ sinh ra `TC_10_OVERFLOW_BOUNDARY_129` và `TC_11_OVERFLOW_LARGE_512`.
- **Nghiệm 3 (Integer Overflow)**: $N = 16384, 65535$ sinh ra `TC_12_INTEGER_OVERFLOW_16384` và `TC_13_INTEGER_OVERFLOW_MAX_UINT16`.

### 2.3. Mô hình phân loại lỗi an toàn phần mềm (CWE Fault Model)
| Chuẩn CWE | Tên phân loại lỗi | Mức độ | Target Gateway | Generated Gateway |
| :--- | :--- | :---: | :---: | :---: |
| **CWE-287 / CWE-798** | Hardcoded Backdoor / Improper Auth | CRITICAL | VULNERABLE (`sat`) | SECURED (`unsat`) |
| **CWE-120 / CWE-122** | Buffer Copy without Bounds Check | CRITICAL | VULNERABLE (`sat`) | SECURED (`unsat`) |
| **CWE-190** | Integer Overflow / 16-bit Wraparound | HIGH | VULNERABLE (`sat`) | SECURED (`unsat`) |
| **CWE-119 / CWE-787** | Improper Memory Hardware Alignment | MEDIUM | VULNERABLE (`sat`) | SECURED (`unsat`) |
| **CWE-1284** | Insufficient Input Length Validation | MEDIUM | VULNERABLE (AST) | SECURED (Safe Guard) |

---

## 3. Quy Trình 3 Giai Đoạn

### Giai đoạn 1: Sinh mã (Code Generation) - `step2_codegen.py`
- Tự động sinh mã nguồn Gateway an toàn (`generated_gateway.py`):
  - Kiểm tra độ dài $\ge 38$ ngay tại header guard.
  - Kiểm tra biên $N \le 128$ trước khi xử lý tải, chặn mọi nguy cơ `MemoryError`.
  - Triệt tiêu cửa sau `DEBUG_BYPASS_999`.
  - Căn chỉnh bộ nhớ: Bổ sung 2 bytes padding thành $Offset = 8 + 4N$, đảm bảo $Offset \pmod 4 = 0$.
  - Tích hợp ghi nhận cạnh đường đi (Path Edge Tracing) phục vụ đo lường Coverage.
- Tự động sinh bộ ca kiểm thử chuyển đổi trạng thái Kripke (`test_cases.json`): 13 ca kiểm thử phủ kín 100% các nhánh chuyển đổi.

### Giai đoạn 2: Kiểm thử tĩnh (Static Testing) - `step3_static_testing.py`
- **Phân tích cú pháp AST**: Quét phát hiện toàn bộ các mẫu vi phạm CWE trên mã cũ và chứng nhận mã sinh an toàn 100%.
- **Kiểm chứng SMT bằng Z3 Solver**: Cả 4 bài toán hình thức đều chứng minh mã sinh đạt `unsat` trên điều kiện lỗi.

### Giai đoạn 3: Kiểm thử động Fuzzing (Dynamic Testing) - `step4_dynamic_testing.py`
- **Ràng buộc kiểm thử Bounded Fuzzing**:
  - Giới hạn số lần lặp: $K = 10,000$ iterations.
  - Giới hạn kích thước gói: $0 \le L \le 512$ bytes.
  - Giới hạn thời gian tối đa mỗi gói: $T \le 50$ms.
- **Phân loại lỗi Crash và Hang**:
  - Số lần Crash (`MemoryError`): Target = 1,497 lần (14.97%) | Generated = 0 lần.
  - Số lần Hang (Treo tiến trình): 0 lần trên cả hai phiên bản.
- **Đo lường Edge Coverage & Path Tracing**:
  - Black-box: Độ bao phủ cạnh chỉ đạt 30.0% - 50.0% với 2 đường đi độc nhất (chủ yếu bị chặn sớm tại `E_LEN_FAIL`).
  - White-box: Độ bao phủ cạnh đạt **100.0%** với 5 đường đi độc nhất, kích hoạt toàn bộ các nhánh rẽ và giá trị biên.

---

## 4. Hướng Dẫn Chạy Toàn Bộ Dự Án

### Cài đặt môi trường:
```bash
pip install -r requirements.txt
```

### Chạy toàn bộ chu trình tích hợp:
```bash
python main.py
```

### Chạy từng giai đoạn độc lập:
```bash
# Giai đoạn 1: Phân tích tham số, cấu trúc Kripke, mệnh đề chuyển đổi & BMC Z3
python step1_kripke_analysis.py

# Giai đoạn 2: Sinh mã Gateway an toàn và sinh test suite từ Z3 counterexamples
python step2_codegen.py

# Giai đoạn 3: Kiểm thử tĩnh (Mô hình phân loại lỗi CWE, AST & Formal SMT)
python step3_static_testing.py

# Giai đoạn 4: Kiểm thử động (Bounded Fuzzing, Crash/Hang, Edge Coverage, Path Tracing)
python step4_dynamic_testing.py
```