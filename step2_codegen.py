import os
import sys
import json
import struct

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

GENERATED_GATEWAY_CODE = r"""import struct

MAGIC_HEADER = b"PASS"
MAX_BUFFER_SIZE = 128

class APIGatewayGenerated:
    def __init__(self):
        self.state = "IDLE"
        self.is_authenticated = False

    def process_request(self, raw_bytes: bytes) -> dict:
        self.state = "PARSING_HEADER"

        if len(raw_bytes) < 38:
            self.state = "BLOCKED"
            return {"status": "ERROR", "state": self.state, "msg": "Invalid packet length"}

        magic = raw_bytes[0:4]
        if magic != MAGIC_HEADER:
            self.state = "BLOCKED"
            return {"status": "ERROR", "state": self.state, "msg": "Invalid magic header"}

        payload_len = struct.unpack(">H", raw_bytes[4:6])[0]

        if payload_len > MAX_BUFFER_SIZE:
            self.state = "BLOCKED"
            return {"status": "ERROR", "state": self.state, "msg": "Payload exceeds maximum allowed size"}

        calculated_offset = 8 + (payload_len * 4)

        token = raw_bytes[6:38].decode("utf-8", errors="ignore").rstrip("\x00")

        self.state = "AUTHENTICATING"
        if token == "SECRET_TOKEN_2026":
            self.is_authenticated = True
        else:
            self.is_authenticated = False
            self.state = "BLOCKED"
            return {"status": "ERROR", "state": self.state, "msg": "Invalid token"}

        self.state = "PROCESSING_PAYLOAD"
        payload = raw_bytes[38:38 + payload_len]

        self.state = "GRANTED"
        return {"status": "SUCCESS", "state": self.state, "data": payload, "offset": calculated_offset}
"""

def generate_safe_gateway_code(output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(GENERATED_GATEWAY_CODE.strip() + "\n")

def generate_kripke_transition_test_suite():
    test_cases = []

    test_cases.append({
        "id": "TC_01_EMPTY_PACKET",
        "description": "Gói tin rỗng kích hoạt chuyển S0 -> S5 (BLOCKED)",
        "kripke_transition": "S0 -> S5",
        "raw_bytes_hex": b"".hex(),
        "expected_target_state": "BLOCKED",
        "expected_generated_state": "BLOCKED"
    })

    test_cases.append({
        "id": "TC_02_SHORT_HEADER",
        "description": "Gói tin chỉ có 4 bytes magic thiếu trường length",
        "kripke_transition": "S0 -> S5",
        "raw_bytes_hex": b"PASS".hex(),
        "expected_target_state": "BLOCKED",
        "expected_generated_state": "BLOCKED"
    })

    test_cases.append({
        "id": "TC_03_SHORT_TOKEN",
        "description": "Gói tin có 6 bytes header nhưng thiếu trường token 32B",
        "kripke_transition": "S1 -> S5",
        "raw_bytes_hex": (b"PASS" + struct.pack(">H", 10)).hex(),
        "expected_target_state": "BLOCKED",
        "expected_generated_state": "BLOCKED"
    })

    test_cases.append({
        "id": "TC_04_INVALID_MAGIC",
        "description": "Gói tin mang Magic Header sai quy định (FAIL)",
        "kripke_transition": "S1 -> S5",
        "raw_bytes_hex": (b"FAIL" + struct.pack(">H", 10) + (b"A" * 32)).hex(),
        "expected_target_state": "BLOCKED",
        "expected_generated_state": "BLOCKED"
    })

    test_cases.append({
        "id": "TC_05_INVALID_TOKEN",
        "description": "Gói tin mang Magic đúng nhưng Token không hợp lệ",
        "kripke_transition": "S2 -> S5",
        "raw_bytes_hex": (b"PASS" + struct.pack(">H", 10) + (b"X" * 32)).hex(),
        "expected_target_state": "BLOCKED",
        "expected_generated_state": "BLOCKED"
    })

    bypass_token = b"DEBUG_BYPASS_999" + (b"\x00" * 16)
    test_cases.append({
        "id": "TC_06_BYPASS_TOKEN_ATTACK",
        "description": "Gói tin tấn công cửa sau DEBUG_BYPASS_999",
        "kripke_transition": "S1 -> S4 (Target) vs S2 -> S5 (Generated)",
        "raw_bytes_hex": (b"PASS" + struct.pack(">H", 10) + bypass_token).hex(),
        "expected_target_state": "GRANTED",
        "expected_generated_state": "BLOCKED"
    })

    valid_token = b"SECRET_TOKEN_2026" + (b"\x00" * 15)
    test_cases.append({
        "id": "TC_07_VALID_PAYLOAD_MIN",
        "description": "Xác thực hợp lệ với Payload tối thiểu (0 bytes)",
        "kripke_transition": "S0 -> S1 -> S2 -> S3 -> S4",
        "raw_bytes_hex": (b"PASS" + struct.pack(">H", 0) + valid_token).hex(),
        "expected_target_state": "GRANTED",
        "expected_generated_state": "GRANTED"
    })

    test_cases.append({
        "id": "TC_08_VALID_PAYLOAD_NOMINAL",
        "description": "Xác thực hợp lệ với Payload 64 bytes thông thường",
        "kripke_transition": "S0 -> S1 -> S2 -> S3 -> S4",
        "raw_bytes_hex": (b"PASS" + struct.pack(">H", 64) + valid_token + (b"D" * 64)).hex(),
        "expected_target_state": "GRANTED",
        "expected_generated_state": "GRANTED"
    })

    test_cases.append({
        "id": "TC_09_VALID_PAYLOAD_MAX",
        "description": "Xác thực hợp lệ tại biên trên an toàn (128 bytes)",
        "kripke_transition": "S0 -> S1 -> S2 -> S3 -> S4",
        "raw_bytes_hex": (b"PASS" + struct.pack(">H", 128) + valid_token + (b"M" * 128)).hex(),
        "expected_target_state": "GRANTED",
        "expected_generated_state": "GRANTED"
    })

    test_cases.append({
        "id": "TC_10_OVERFLOW_BOUNDARY_129",
        "description": "Tấn công tràn bộ đệm tại giá trị biên 129 bytes (> 128)",
        "kripke_transition": "S3 -> S6 (Target Crash) vs S1 -> S5 (Generated Blocked)",
        "raw_bytes_hex": (b"PASS" + struct.pack(">H", 129) + valid_token + (b"E" * 129)).hex(),
        "expected_target_state": "CRASH_ERROR",
        "expected_generated_state": "BLOCKED"
    })

    test_cases.append({
        "id": "TC_11_OVERFLOW_LARGE_512",
        "description": "Tấn công tràn bộ đệm tải lớn 512 bytes",
        "kripke_transition": "S3 -> S6 (Target Crash) vs S1 -> S5 (Generated Blocked)",
        "raw_bytes_hex": (b"PASS" + struct.pack(">H", 512) + valid_token + (b"O" * 512)).hex(),
        "expected_target_state": "CRASH_ERROR",
        "expected_generated_state": "BLOCKED"
    })

    test_cases.append({
        "id": "TC_12_INTEGER_OVERFLOW_16384",
        "description": "Tấn công tràn số nguyên phép tính offset (payload_len = 16384)",
        "kripke_transition": "S3 -> S6 (Target Crash) vs S1 -> S5 (Generated Blocked)",
        "raw_bytes_hex": (b"PASS" + struct.pack(">H", 16384) + valid_token + (b"I" * 200)).hex(),
        "expected_target_state": "CRASH_ERROR",
        "expected_generated_state": "BLOCKED"
    })

    test_cases.append({
        "id": "TC_13_INTEGER_OVERFLOW_MAX_UINT16",
        "description": "Tấn công giá trị cực đại uint16 (payload_len = 65535)",
        "kripke_transition": "S3 -> S6 (Target Crash) vs S1 -> S5 (Generated Blocked)",
        "raw_bytes_hex": (b"PASS" + struct.pack(">H", 65535) + valid_token + (b"Z" * 200)).hex(),
        "expected_target_state": "CRASH_ERROR",
        "expected_generated_state": "BLOCKED"
    })

    return test_cases

def run_code_generation():
    print("=" * 90)
    print("GIAI ĐOẠN 1: SINH MÃ TỰ ĐỘNG DỰA TRÊN ĐẶC TẢ VÀ CẤU TRÚC KRIPKE (CODE GENERATION)")
    print("=" * 90)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    generated_gateway_file = os.path.join(base_dir, "generated_gateway.py")
    test_cases_file = os.path.join(base_dir, "test_cases.json")

    print(f"\n[1] TIẾN HÀNH SINH MÃ NGUỒN GATEWAY AN TOÀN:")
    print(f"  -> File đích: {generated_gateway_file}")
    generate_safe_gateway_code(generated_gateway_file)
    print("  -> Đã sinh thành công APIGatewayGenerated tuân thủ đầy đủ các guard của Cấu trúc Kripke:")
    print("     + Guard 1: len(packet) >= 38 kiểm tra độ dài trước khi cắt token.")
    print("     + Guard 2: magic == b'PASS' chặn ngay tại header parser.")
    print("     + Guard 3: payload_len <= 128 loại bỏ hoàn toàn khả năng rơi vào S6: CRASH_ERROR.")
    print("     + Guard 4: Triệt tiêu cửa sau DEBUG_BYPASS_999, chỉ cấp quyền khi token hợp lệ.")
    print("     + Guard 5: calculated_offset = 8 + 4*N bảo đảm căn chỉnh 4-byte bộ nhớ (offset % 4 == 0).")

    print(f"\n[2] TIẾN HÀNH SINH BỘ DỮ LIỆU KIỂM THỬ CHUYỂN TRẠNG THÁI KRIPKE:")
    print(f"  -> File đích: {test_cases_file}")
    test_cases = generate_kripke_transition_test_suite()
    with open(test_cases_file, "w", encoding="utf-8") as f:
        json.dump(test_cases, f, ensure_ascii=False, indent=2)
    print(f"  -> Đã sinh thành công {len(test_cases)} ca kiểm thử bao phủ 100% các nhánh chuyển đổi của Kripke.")

    row_fmt = "{:<25} | {:<42} | {:<22}"
    print("\n" + row_fmt.format("Mã ca kiểm thử", "Mục tiêu kiểm thử Kripke", "Chuyển trạng thái"))
    print("-" * 95)
    for tc in test_cases:
        print(row_fmt.format(tc["id"], tc["description"][:40], tc["kripke_transition"][:20]))

    print("\n" + "=" * 90)
    print("HOÀN THÀNH GIAI ĐOẠN 1: SINH MÃ VÀ SINH BỘ DỮ LIỆU KIỂM THỬ THÀNH CÔNG")
    print("=" * 90)

if __name__ == "__main__":
    run_code_generation()
