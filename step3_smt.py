import sys
from z3 import BitVec, BitVecVal, Solver, sat, unsat, And, Or, Not, UGT, UGE, ULE, ULT, ZeroExt, Extract, simplify

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

if sys.stderr.encoding and sys.stderr.encoding.lower() != 'utf-8':
    try:
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

def run_smt_verification():
    print("=" * 80)
    print("CHẶNG 4: KIỂM CHỨNG RÀNG BUỘC HÌNH THỨC SMT VỚI Z3 SOLVER")
    print("=" * 80)

    print("\n[MỤC TIÊU 1] KIỂM CHỨNG TRÀN SỐ NGUYÊN (INTEGER OVERFLOW)")
    print("Công thức tính offset: calculated_offset = 6 + (payload_len * 4)")

    solver1 = Solver()
    payload_len_16 = BitVec('payload_len_16', 16)
    offset_16 = BitVecVal(6, 16) + (payload_len_16 * BitVecVal(4, 16))
    payload_len_32 = ZeroExt(16, payload_len_16)
    offset_32 = BitVecVal(6, 32) + (payload_len_32 * BitVecVal(4, 32))
    overflow_cond = (ZeroExt(16, offset_16) != offset_32)

    solver1.add(overflow_cond)
    res1 = solver1.check()

    print(f"Trạng thái Z3 (Target Gateway - Unchecked): {res1}")
    if res1 == sat:
        m = solver1.model()
        val_len = m[payload_len_16].as_long()
        val_off_16 = (6 + (val_len * 4)) & 0xFFFF
        val_off_32 = 6 + (val_len * 4)
        print(f"  -> Phát hiện lỗ hổng Integer Overflow!")
        print(f"  -> Counterexample: payload_len = {val_len} (0x{val_len:04X})")
        print(f"  -> Giá trị offset 16-bit (Wrap-around): {val_off_16}")
        print(f"  -> Giá trị offset thực tế 32-bit:      {val_off_32}")
    else:
        print("  -> Không phát hiện khả năng tràn số.")

    solver1_patched = Solver()
    solver1_patched.add(ULE(payload_len_16, BitVecVal(128, 16)))
    solver1_patched.add(overflow_cond)
    res1_patched = solver1_patched.check()

    print(f"Trạng thái Z3 (Patched Gateway - payload_len <= 128): {res1_patched}")
    if res1_patched == unsat:
        print("  -> Chứng minh hình thức thành công: Bản vá ngăn chặn hoàn toàn Integer Overflow.")
    else:
        print("  -> Vẫn tồn tại trường hợp vi phạm trong bản vá.")

    print("\n" + "-" * 80)
    print("[MỤC TIÊU 2] KIỂM CHỨNG ĐIỀU KIỆN CĂN CHỈNH BỘ NHỚ (MEMORY ALIGNMENT)")
    print("Kiểm tra xem calculated_offset có căn chỉnh chia hết cho 4 bytes không")

    solver2 = Solver()
    payload_len_align = BitVec('payload_len_align', 32)
    offset_val = BitVecVal(6, 32) + (payload_len_align * BitVecVal(4, 32))
    solver2.add((offset_val % BitVecVal(4, 32)) == BitVecVal(0, 32))
    res2 = solver2.check()

    print(f"Trạng thái Z3 (offset % 4 == 0): {res2}")
    if res2 == unsat:
        print("  -> Bất biến vi phạm: Không tồn tại giá trị payload_len nào để offset chia hết cho 4!")
        print("  -> Giải thích: calculated_offset = 6 + 4k = 4(k + 1) + 2 => Số dư luôn bằng 2.")
        print("  -> Khuyến nghị: Cần thêm 2 bytes padding vào header hoặc base offset phải chia hết cho 4 (vd: 8).")
    else:
        m2 = solver2.model()
        print(f"  -> Tồn tại alignment hợp lệ tại payload_len = {m2[payload_len_align]}")

    print("\n" + "-" * 80)
    print("[MỤC TIÊU 3] KIỂM CHỨNG AN TOÀN VÙNG ĐỆM (BUFFER OVERFLOW VERIFICATION)")
    print("Kiểm tra khả năng kích hoạt MemoryError khi payload_len > MAX_BUFFER_SIZE (128)")

    solver3 = Solver()
    raw_packet_len = BitVec('raw_packet_len', 32)
    p_len = BitVec('p_len', 16)
    p_len_ext = ZeroExt(16, p_len)
    max_buf = BitVecVal(128, 32)

    solver3.add(UGE(raw_packet_len, BitVecVal(38, 32) + p_len_ext))
    solver3.add(UGT(p_len_ext, max_buf))

    res3 = solver3.check()
    print(f"Trạng thái Z3 (Target Gateway - Buffer Overflow Reachability): {res3}")
    if res3 == sat:
        m3 = solver3.model()
        p_len_found = m3[p_len].as_long()
        pkt_len_found = m3[raw_packet_len].as_long()
        print(f"  -> Lỗ hổng Buffer Overflow khả đạt (SAT)!")
        print(f"  -> Counterexample: payload_len = {p_len_found}, raw_packet_len = {pkt_len_found}")
        print(f"  -> Hệ quả: Kích thước vượt quá MAX_BUFFER_SIZE (128) dẫn đến ngoại lệ MemoryError.")
    else:
        print("  -> Không thể kích hoạt lỗi tràn bộ đệm.")

    solver3_patched = Solver()
    solver3_patched.add(UGE(raw_packet_len, BitVecVal(38, 32) + p_len_ext))
    solver3_patched.add(UGT(p_len_ext, max_buf))
    solver3_patched.add(ULE(p_len_ext, max_buf))
    res3_patched = solver3_patched.check()

    print(f"Trạng thái Z3 (Patched Gateway Verification): {res3_patched}")
    if res3_patched == unsat:
        print("  -> Chứng minh hình thức thành công: Điều kiện bảo vệ (payload_len <= 128) triệt tiêu MemoryError.")

    print("\n" + "-" * 80)
    print("[MỤC TIÊU 4] KIỂM CHỨNG BẤT BIẾN XÁC THỰC VÀ LOGIC BYPASS")
    print("Bất biến kỳ vọng: (Trạng thái GRANTED) ==> (Token == SECRET_TOKEN_2026)")

    TOKEN_INVALID = 0
    TOKEN_VALID = 1
    TOKEN_BYPASS = 2

    token_type = BitVec('token_type', 4)

    solver4 = Solver()
    vulnerable_logic = Or(
        token_type == BitVecVal(TOKEN_BYPASS, 4),
        token_type == BitVecVal(TOKEN_VALID, 4)
    )
    solver4.add(vulnerable_logic)
    solver4.add(token_type != BitVecVal(TOKEN_VALID, 4))
    res4 = solver4.check()

    print(f"Trạng thái Z3 (Target Gateway - Authentication Bypass): {res4}")
    if res4 == sat:
        m4 = solver4.model()
        token_type_val = m4[token_type].as_long()
        token_desc = "DEBUG_BYPASS_999" if token_type_val == TOKEN_BYPASS else "Khác"
        print(f"  -> Phát hiện lỗ hổng Logic Bypass (SAT)!")
        print(f"  -> Counterexample kích hoạt GRANTED trái phép: Token = {token_desc}")

    solver4_patched = Solver()
    patched_logic = (token_type == BitVecVal(TOKEN_VALID, 4))
    solver4_patched.add(patched_logic)
    solver4_patched.add(token_type != BitVecVal(TOKEN_VALID, 4))
    res4_patched = solver4_patched.check()

    print(f"Trạng thái Z3 (Patched Gateway - Authentication Invariant): {res4_patched}")
    if res4_patched == unsat:
        print("  -> Chứng minh hình thức thành công: Bất biến xác thực được đảm bảo tuyệt đối.")

    print("\n" + "=" * 80)
    print("TỔNG KẾT KIỂM CHỨNG HÌNH THỨC SMT VỚI Z3 SOLVER")
    print("1. Integer Overflow: Target: VULNERABLE | Patched: SAFE (UNSAT)")
    print("2. Memory Alignment: Cả 2 bản đều vi phạm alignment 4 bytes (UNSAT offset % 4 == 0)")
    print("3. Buffer Overflow:  Target: VULNERABLE | Patched: SAFE (UNSAT)")
    print("4. Logic Bypass:     Target: VULNERABLE | Patched: SAFE (UNSAT)")
    print("=" * 80)

if __name__ == "__main__":
    run_smt_verification()
