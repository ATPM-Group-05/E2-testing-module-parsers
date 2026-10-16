import sys
from z3 import BitVec, BitVecVal, Solver, sat, unsat, And, Or, Not, Implies, ZeroExt, ULE, UGT

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

if sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

STATE_IDLE = 0
STATE_PARSING_HEADER = 1
STATE_AUTHENTICATING = 2
STATE_PROCESSING_PAYLOAD = 3
STATE_GRANTED = 4
STATE_BLOCKED = 5
STATE_CRASH_ERROR = 6

STATE_NAMES = {
    STATE_IDLE: "S0: IDLE",
    STATE_PARSING_HEADER: "S1: PARSING_HEADER",
    STATE_AUTHENTICATING: "S2: AUTHENTICATING",
    STATE_PROCESSING_PAYLOAD: "S3: PROCESSING_PAYLOAD",
    STATE_GRANTED: "S4: GRANTED",
    STATE_BLOCKED: "S5: BLOCKED",
    STATE_CRASH_ERROR: "S6: CRASH_ERROR"
}

STATE_SPECS = {
    STATE_IDLE: ("Khởi tạo / Chờ nhận gói tin", "len(raw_bytes) >= 0", "is_idle"),
    STATE_PARSING_HEADER: ("Đọc Magic (4B) và Độ dài Payload (2B)", "len(raw_bytes) >= 6", "hdr_parsed"),
    STATE_AUTHENTICATING: ("Xác thực chuỗi Token bảo mật (32B)", "magic == 'PASS' and len >= 38", "tok_checking"),
    STATE_PROCESSING_PAYLOAD: ("Kiểm tra biên bộ đệm và trích xuất dữ liệu", "token == 'SECRET_TOKEN_2026'", "buf_processing"),
    STATE_GRANTED: ("Cấp quyền truy cập hệ thống (Terminal Success)", "is_authenticated == True", "is_granted"),
    STATE_BLOCKED: ("Từ chối an toàn khi phát hiện sai phạm (Terminal Safe)", "packet_malformed or token_invalid", "is_blocked"),
    STATE_CRASH_ERROR: ("Lỗi sập do tràn bộ đệm MemoryError (Terminal Panic)", "payload_len > 128 (Unchecked)", "is_crash")
}

TOKEN_INVALID = 0
TOKEN_VALID = 1
TOKEN_BYPASS = 2

def display_parameter_and_combinatorial_analysis():
    print("=" * 90)
    print("PHẦN 1: PHÂN TÍCH THAM SỐ VÀ TÍNH TỔ HỢP XÁC ĐỊNH THAM SỐ CHÍNH (GATEWAY AUTH)")
    print("=" * 90)

    print("\n1. BẢNG THAM SỐ ĐẦU VÀO CỦA MODULE PARSER:")
    param_table = [
        ("P1", "raw_packet_len", "Độ dài gói tin thô (L)", "int [0, +inf)", "L < 6, 6 <= L < 38, L >= 38"),
        ("P2", "magic_header", "Mã định danh giao thức (M)", "bytes [4B]", "M == b'PASS', M != b'PASS'"),
        ("P3", "payload_len", "Độ dài dữ liệu khai báo (N)", "uint16 [0, 65535]", "N <= 128, 128 < N <= 16382, N >= 16383"),
        ("P4", "token", "Chuỗi token xác thực (T)", "bytes [32B]", "VALID (SECRET_TOKEN), BYPASS (DEBUG), INVALID"),
        ("P5", "payload_data", "Dữ liệu payload thực tế (D)", "bytes [L-38]", "Thiếu (L < 38+N), Đủ (L >= 38+N)"),
        ("P6", "calculated_offset", "Offset con trỏ bộ nhớ (Off)", "uint32", "Off = 6 + 4N (Lệch) vs Off = 8 + 4N (Chuẩn)"),
        ("P7", "is_authenticated", "Cờ trạng thái xác thực nội bộ", "bool", "True, False")
    ]
    row_fmt = "{:<5} | {:<18} | {:<32} | {:<18} | {:<35}"
    print(row_fmt.format("Ký hiệu", "Tên tham số", "Ý nghĩa ngữ nghĩa", "Miền giá trị", "Phân hoạch tương đương"))
    print("-" * 115)
    for p in param_table:
        print(row_fmt.format(p[0], p[1], p[2], p[3], p[4]))

    print("\n2. PHÂN TÍCH TÍNH TỔ HỢP VÀ RÚT GỌN KHÔNG GIAN THAM SỐ:")
    print("  - Không gian trạng thái thô mức bit: 2^(8*L) -> Bùng nổ tổ hợp vô hạn.")
    print("  - Áp dụng phân hoạch tương đương (Equivalence Partitioning) và phân tích giá trị biên (BVA):")
    print("    + P1 (Độ dài gói):       3 phân hoạch (L < 6, 6 <= L < 38, L >= 38)")
    print("    + P2 (Magic Header):     2 phân hoạch (Đúng, Sai)")
    print("    + P3 (Payload Length):   3 phân hoạch (Biên an toàn <= 128, Tràn bộ đệm > 128, Tràn số nguyên >= 16383)")
    print("    + P4 (Token xác thực):   3 phân hoạch (Hợp lệ chính quy, Cửa sau Debug, Không hợp lệ)")
    print("  - Tổng số tổ hợp phân hoạch tương đương ban đầu: 3 * 2 * 3 * 3 = 54 tổ hợp.")
    print("  - Rút gọn tổ hợp (Combinatorial Reduction) theo Guard Conditions của Parser:")
    print("    + Khi L < 6: Rẽ nhánh trực tiếp sang BLOCKED (không phụ thuộc P2, P3, P4).")
    print("    + Khi Magic sai: Rẽ nhánh trực tiếp sang BLOCKED (loại bỏ phụ thuộc P3, P4).")
    print("    + 4 tham số chính tác động trực tiếp chuyển đổi trạng thái: (P_len_valid, P_magic_valid, P_token_type, P_buffer_safe).")

    print("\n3. ĐẶC TẢ HÌNH THỨC CÁC TRẠNG THÁI (FORMAL STATE SPECIFICATIONS):")
    spec_fmt = "{:<24} | {:<48} | {:<30} | {:<15}"
    print(spec_fmt.format("Trạng thái", "Mô tả ngữ nghĩa hình thức", "Điều kiện bất biến / Vào", "Mệnh đề AP"))
    print("-" * 125)
    for s_idx, (desc, entry_cond, ap_prop) in STATE_SPECS.items():
        print(spec_fmt.format(STATE_NAMES[s_idx], desc, entry_cond, ap_prop))

    print("\n4. HỆ THỐNG RÀNG BUỘC CHUYỂN TRẠNG THÁI (CONSTRAINTS):")
    print("  - Ràng buộc 1 (Precondition Header): Chuyển S0 -> S1 yêu cầu len(packet) >= 6.")
    print("  - Ràng buộc 2 (Guard Magic): Chuyển S1 -> S2 yêu cầu Magic == 'PASS'; nếu sai chuyển S1 -> S5 (BLOCKED).")
    print("  - Ràng buộc 3 (Guard Token): Chuyển S2 -> S3 yêu cầu Token == 'SECRET_TOKEN_2026'.")
    print("    * Lỗ hổng: Token == 'DEBUG_BYPASS_999' nhảy cóc trái phép S1 -> S4 (GRANTED) bỏ qua thẩm định.")
    print("  - Ràng buộc 4 (Guard Buffer Size): Chuyển S3 -> S4 yêu cầu payload_len <= 128.")
    print("    * Lỗ hổng: Nếu payload_len > 128 không chặn trước, cấp phát sẽ kích hoạt S6 (CRASH_ERROR).")
    print("  - Ràng buộc 5 (Safety Invariant 1): AG(State == S4 => Token == VALID_TOKEN).")
    print("  - Ràng buộc 6 (Safety Invariant 2): AG(State != S6) (Loại bỏ hoàn toàn trạng thái Crash).")
    print("  - Ràng buộc 7 (Memory Alignment):  AG(calculated_offset % 4 == 0).")

def display_kripke_structure():
    print("\n" + "=" * 90)
    print("PHẦN 2: CẤU TRÚC KRIPKE VÀ CÁC MỆNH ĐỀ CHUYỂN ĐỔI TRẠNG THÁI (TRANSITION PROPOSITIONS)")
    print("=" * 90)

    print("\n1. ĐỊNH NGHĨA HÌNH THỨC CẤU TRÚC KRIPKE M = (S, S0, R, L, AP):")
    print("  - S  = {S0: IDLE, S1: PARSING_HEADER, S2: AUTHENTICATING, S3: PROCESSING_PAYLOAD,")
    print("          S4: GRANTED, S5: BLOCKED, S6: CRASH_ERROR}")
    print("  - S0 = {S0}")
    print("  - AP = {is_idle, hdr_parsed, tok_checking, buf_processing, is_granted, is_blocked, is_crash}")
    print("  - L(s): Ánh xạ từng trạng thái s tới tập con các mệnh đề nguyên tử AP đúng tại s.")
    print("  - R: Quan hệ chuyển đổi toàn phần R subset S x S (Toàn bộ các trạng thái kết thúc có Self-Loop).")

    print("\n2. ĐẶC TẢ CÁC MỆNH ĐỀ CHUYỂN ĐỔI TRẠNG THÁI (STATE TRANSITION PROPOSITIONS):")
    trans_propositions = [
        ("Phi(S0 -> S1)", "(s == S0) and (L >= 6) and (s' == S1)"),
        ("Phi(S0 -> S5)", "(s == S0) and (L < 6) and (s' == S5)"),
        ("Phi(S1 -> S2)", "(s == S1) and (M == 'PASS') and (T != 'DEBUG_BYPASS_999') and (s' == S2)"),
        ("Phi(S1 -> S4)*", "(s == S1) and (M == 'PASS') and (T == 'DEBUG_BYPASS_999') and (s' == S4) [BACKDOOR BYPASS]"),
        ("Phi(S1 -> S5)", "(s == S1) and (M != 'PASS' or L < 38) and (s' == S5)"),
        ("Phi(S2 -> S3)", "(s == S2) and (T == 'SECRET_TOKEN_2026') and (s' == S3)"),
        ("Phi(S2 -> S5)", "(s == S2) and (T != 'SECRET_TOKEN_2026') and (s' == S5)"),
        ("Phi(S3 -> S4)", "(s == S3) and (N <= 128) and (s' == S4)"),
        ("Phi(S3 -> S6)*", "(s == S3) and (N > 128) and (s' == S6) [BUFFER OVERFLOW MEMORYERROR]"),
        ("Phi_sink", "(s in {S4, S5, S6}) and (s' == s) [SELF-LOOP TOÀN PHẦN]")
    ]
    prop_fmt = "  {:<16} <=> {:<85}"
    for p_id, p_formula in trans_propositions:
        print(prop_fmt.format(p_id, p_formula))
    print("  Quan hệ chuyển đổi toàn cục: T(s, s') <=> \u2228 Phi(Si, Sj)")

    print("\n3. MA TRẬN CHUYỂN ĐỔI TRẠNG THÁI KRIPKE (KRIPKE TRANSITION MATRIX):")
    header_str = "{:<22} | " + " | ".join(["{:<5}"] * 7)
    print(header_str.format("Trạng thái nguồn (s)", "S0", "S1", "S2", "S3", "S4", "S5", "S6"))
    print("-" * 75)
    
    matrix = [
        ("S0: IDLE",               ["0", "1", "0", "0", "0", "1", "0"]),
        ("S1: PARSING_HEADER",     ["0", "0", "1", "0", "1*", "1", "0"]),
        ("S2: AUTHENTICATING",     ["0", "0", "0", "1", "0", "1", "0"]),
        ("S3: PROCESSING_PAYLOAD", ["0", "0", "0", "0", "1", "1", "1*"]),
        ("S4: GRANTED (Sink)",     ["0", "0", "0", "0", "1", "0", "0"]),
        ("S5: BLOCKED (Sink)",     ["0", "0", "0", "0", "0", "1", "0"]),
        ("S6: CRASH_ERROR (Sink)", ["0", "0", "0", "0", "0", "0", "1"])
    ]
    
    for row_name, cols in matrix:
        print(header_str.format(row_name, *cols))

    print("\n  Ghi chú: '1*' biểu thị đường chuyển đổi chứa lỗ hổng an toàn:")
    print("    - (S1 -> S4): Lỗ hổng Logic Bypass qua token cửa sau DEBUG_BYPASS_999.")
    print("    - (S3 -> S6): Lỗ hổng tràn bộ đệm MemoryError do thiếu guard kiểm tra biên trước khi nạp.")
    print("    - (S4, S4), (S5, S5), (S6, S6): Self-loops bảo đảm tính toàn phần của Cấu trúc Kripke.")

def run_bmc_kripke_verification(max_k=4):
    print("\n" + "=" * 90)
    print("PHẦN 3: KIỂM CHỨNG MÔ HÌNH HỮU HẠN (BOUNDED MODEL CHECKING - BMC) VÀ CƠ SỞ SINH TEST CASE")
    print("=" * 90)
    print("Cơ sở toán học sinh test case từ BMC/Z3:")
    print("  Khi giải phủ định bất biến an toàn not(Invariant), nếu SAT, nghiệm mô hình Z3 (Counterexample)")
    print("  chính là bộ dữ liệu kích hoạt lỗi cụ thể, được sử dụng trực tiếp để tổng hợp Test Cases biên.")
    print(f"\nĐộ sâu kiểm chứng Kripke Unrolling: K = 0 -> {max_k}")

    for k in range(1, max_k + 1):
        print("\n" + "-" * 90)
        print(f"[*] BƯỚC MỞ RỘNG KRIPKE UNROLL K = {k}")

        solver_vuln = Solver()
        states = [BitVec(f"s_{i}", 4) for i in range(k + 1)]
        payload_len = BitVec("payload_len", 16)
        token_type = BitVec("token_type", 4)
        magic_ok = BitVec("magic_ok", 1)
        pkt_len_ok = BitVec("pkt_len_ok", 1)

        solver_vuln.add(states[0] == BitVecVal(STATE_IDLE, 4))

        for i in range(k):
            sc = states[i]
            sn = states[i + 1]

            t_s0 = Implies(
                sc == BitVecVal(STATE_IDLE, 4),
                And(
                    Implies(pkt_len_ok == BitVecVal(1, 1), sn == BitVecVal(STATE_PARSING_HEADER, 4)),
                    Implies(pkt_len_ok == BitVecVal(0, 1), sn == BitVecVal(STATE_BLOCKED, 4))
                )
            )

            t_s1 = Implies(
                sc == BitVecVal(STATE_PARSING_HEADER, 4),
                And(
                    Implies(magic_ok == BitVecVal(0, 1), sn == BitVecVal(STATE_BLOCKED, 4)),
                    Implies(
                        magic_ok == BitVecVal(1, 1),
                        And(
                            Implies(token_type == BitVecVal(TOKEN_BYPASS, 4), sn == BitVecVal(STATE_GRANTED, 4)),
                            Implies(token_type != BitVecVal(TOKEN_BYPASS, 4), sn == BitVecVal(STATE_AUTHENTICATING, 4))
                        )
                    )
                )
            )

            t_s2 = Implies(
                sc == BitVecVal(STATE_AUTHENTICATING, 4),
                And(
                    Implies(token_type == BitVecVal(TOKEN_VALID, 4), sn == BitVecVal(STATE_PROCESSING_PAYLOAD, 4)),
                    Implies(token_type != BitVecVal(TOKEN_VALID, 4), sn == BitVecVal(STATE_BLOCKED, 4))
                )
            )

            t_s3 = Implies(
                sc == BitVecVal(STATE_PROCESSING_PAYLOAD, 4),
                And(
                    Implies(UGT(ZeroExt(16, payload_len), BitVecVal(128, 32)), sn == BitVecVal(STATE_CRASH_ERROR, 4)),
                    Implies(ULE(ZeroExt(16, payload_len), BitVecVal(128, 32)), sn == BitVecVal(STATE_GRANTED, 4))
                )
            )

            t_sinks = Implies(
                Or(
                    sc == BitVecVal(STATE_GRANTED, 4),
                    sc == BitVecVal(STATE_BLOCKED, 4),
                    sc == BitVecVal(STATE_CRASH_ERROR, 4)
                ),
                sn == sc
            )

            solver_vuln.add(And(t_s0, t_s1, t_s2, t_s3, t_sinks))

        prop_crash = (states[k] == BitVecVal(STATE_CRASH_ERROR, 4))
        solver_vuln.push()
        solver_vuln.add(prop_crash)
        res_crash = solver_vuln.check()
        print(f"  -> Kiểm tra tính khả đạt của trạng thái lỗi Crash (Memory Safety): {res_crash}")
        if res_crash == sat:
            m = solver_vuln.model()
            val_len = m[payload_len].as_long()
            trace = [m[s].as_long() for s in states]
            trace_names = " -> ".join([STATE_NAMES[t] for t in trace])
            print(f"     [!] SAT: Phát hiện vết phản chứng (Counterexample) kích hoạt Crash tại K={k}")
            print(f"     [!] Đường dẫn trạng thái Kripke: {trace_names}")
            print(f"     [!] Giá trị kích hoạt: payload_len = {val_len} (vượt ngưỡng MAX_BUFFER_SIZE 128)")
            print(f"     [+] Cơ sở sinh test case: Tổng hợp thành TC_10 (payload_len=129) và TC_11 (payload_len=512)")
        solver_vuln.pop()

        prop_bypass = And(
            states[k] == BitVecVal(STATE_GRANTED, 4),
            token_type == BitVecVal(TOKEN_BYPASS, 4)
        )
        solver_vuln.push()
        solver_vuln.add(prop_bypass)
        res_bypass = solver_vuln.check()
        print(f"  -> Kiểm tra tính khả đạt của cửa sau logic (Auth Bypass Invariant): {res_bypass}")
        if res_bypass == sat:
            m = solver_vuln.model()
            trace = [m[s].as_long() for s in states]
            trace_names = " -> ".join([STATE_NAMES[t] for t in trace])
            print(f"     [!] SAT: Phát hiện vết phản chứng bypass xác thực tại K={k}")
            print(f"     [!] Đường dẫn trạng thái Kripke: {trace_names}")
            print(f"     [!] Cơ chế: Token DEBUG_BYPASS_999 chuyển thẳng sang GRANTED mà không qua xác thực")
            print(f"     [+] Cơ sở sinh test case: Tổng hợp thành TC_06 (Token=DEBUG_BYPASS_999)")
        solver_vuln.pop()

    print("\n" + "=" * 90)
    print("TỔNG KẾT BƯỚC 1:")
    print("1. Đã phân tích chi tiết tham số, tính tổ hợp và xác định các tham số chính của Gateway Auth.")
    print("2. Đã đặc tả hình thức 7 trạng thái và toàn bộ các mệnh đề chuyển đổi trạng thái Phi(Si, Sj).")
    print("3. Đã xây dựng cấu trúc Kripke chính quy và ma trận chuyển đổi toàn phần.")
    print("4. BMC Z3 đã chứng minh vết phản chứng vi phạm an toàn, tạo cơ sở toán học sinh Test Cases.")
    print("=" * 90)

def run_kripke_analysis():
    display_parameter_and_combinatorial_analysis()
    display_kripke_structure()
    run_bmc_kripke_verification(max_k=4)

if __name__ == "__main__":
    run_kripke_analysis()
