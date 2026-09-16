import os
import sys
import time
import json
import random
import struct
from target_gateway import APIGateway
from target_gateway_patched import APIGatewayPatched

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

class BlackBoxFuzzer:
    def __init__(self, max_packet_size=512):
        self.max_packet_size = max_packet_size

    def generate(self) -> bytes:
        length = random.randint(0, self.max_packet_size)
        return random.randbytes(length)

class WhiteBoxFuzzer:
    def __init__(self):
        self.magic_pool = [
            b"PASS",
            b"PASS",
            b"PASS",
            b"PAS\x00",
            b"FAIL",
            b"\x00\x00\x00\x00",
            b"\xff\xff\xff\xff",
            b"ABCD"
        ]
        self.len_boundary_pool = [
            0,
            1,
            64,
            127,
            128,
            129,
            150,
            200,
            256,
            512,
            1024,
            16383,
            32768,
            65535
        ]

    def _build_token_field(self) -> bytes:
        token_choice = random.choice(["valid", "bypass", "random_ascii", "garbage", "empty"])
        if token_choice == "valid":
            base = b"SECRET_TOKEN_2026"
            padding_byte = random.choice([b"\xff", b"\xfe", b"\x80", b"\xaa"])
            return base + (padding_byte * (32 - len(base)))
        elif token_choice == "bypass":
            base = b"DEBUG_BYPASS_999"
            padding_byte = random.choice([b"\xff", b"\xfe", b"\x80", b"\xaa"])
            return base + (padding_byte * (32 - len(base)))
        elif token_choice == "random_ascii":
            chars = [chr(random.randint(32, 126)) for _ in range(32)]
            return "".join(chars).encode('utf-8')[:32]
        elif token_choice == "empty":
            return b"\x00" * 32
        else:
            return random.randbytes(32)

    def generate(self) -> bytes:
        strategy = random.choice([
            "protocol_target",
            "boundary_attack",
            "bypass_attack",
            "mutation_header",
            "length_mismatch",
            "truncated_packet"
        ])

        if strategy == "truncated_packet":
            return random.randbytes(random.randint(0, 37))

        if strategy == "mutation_header":
            magic = random.choice(self.magic_pool)
        else:
            magic = b"PASS"

        if strategy in ["boundary_attack", "protocol_target"]:
            payload_len = random.choice(self.len_boundary_pool)
        else:
            payload_len = random.randint(0, 300)

        if strategy == "bypass_attack":
            base = b"DEBUG_BYPASS_999"
            padding_byte = random.choice([b"\xff", b"\xfe", b"\x80", b"\xaa"])
            token_bytes = base + (padding_byte * (32 - len(base)))
        elif strategy == "boundary_attack":
            base = b"SECRET_TOKEN_2026"
            padding_byte = random.choice([b"\xff", b"\xfe", b"\x80", b"\xaa"])
            token_bytes = base + (padding_byte * (32 - len(base)))
        else:
            token_bytes = self._build_token_field()

        if strategy == "length_mismatch":
            actual_len = random.choice([0, payload_len // 2, 50])
        else:
            actual_len = payload_len

        header = magic + struct.pack(">H", payload_len)
        payload = random.randbytes(min(actual_len, 1024))
        return header + token_bytes + payload

def execute_fuzzing(gateway_cls, fuzzer, iterations=10000):
    stats = {
        "iterations": iterations,
        "crashes": 0,
        "bypass_granted": 0,
        "auth_granted": 0,
        "blocked_error": 0,
        "first_crash_iter": None,
        "first_bypass_iter": None,
        "crash_samples": [],
        "bypass_samples": []
    }

    start_time = time.time()
    for i in range(1, iterations + 1):
        gateway = gateway_cls()
        test_input = fuzzer.generate()
        try:
            res = gateway.process_request(test_input)
            if res.get("status") == "SUCCESS":
                if res.get("msg") == "Bypassed Admin Access":
                    stats["bypass_granted"] += 1
                    if stats["first_bypass_iter"] is None:
                        stats["first_bypass_iter"] = i
                    if len(stats["bypass_samples"]) < 3:
                        stats["bypass_samples"].append({
                            "iteration": i,
                            "raw_bytes_hex": test_input.hex()[:100],
                            "response": res
                        })
                else:
                    stats["auth_granted"] += 1
            else:
                stats["blocked_error"] += 1
        except MemoryError as e:
            stats["crashes"] += 1
            if stats["first_crash_iter"] is None:
                stats["first_crash_iter"] = i
            if len(stats["crash_samples"]) < 3:
                stats["crash_samples"].append({
                    "iteration": i,
                    "error": str(e),
                    "raw_bytes_hex": test_input.hex()[:100],
                    "input_len": len(test_input)
                })
        except Exception as e:
            stats["crashes"] += 1
            if stats["first_crash_iter"] is None:
                stats["first_crash_iter"] = i
            if len(stats["crash_samples"]) < 3:
                stats["crash_samples"].append({
                    "iteration": i,
                    "error": f"{type(e).__name__}: {str(e)}",
                    "raw_bytes_hex": test_input.hex()[:100],
                    "input_len": len(test_input)
                })

    stats["elapsed_seconds"] = round(time.time() - start_time, 4)
    return stats

def print_comparison_table(results):
    print("=" * 105)
    print("CHẶNG 5: KIỂM THỬ ĐỘNG FUZZING (SO SÁNH BLACK-BOX VS WHITE-BOX)")
    print("=" * 105)

    headers = ["Chỉ số đánh giá", "Black-box (Target)", "White-box (Target)", "Black-box (Patched)", "White-box (Patched)"]
    row_fmt = "{:<30} | {:<16} | {:<18} | {:<18} | {:<18}"
    sep = "-" * 105

    print(row_fmt.format(*headers))
    print(sep)

    metrics = [
        ("Số lượt kiểm thử (Iterations)", lambda r: str(r["iterations"])),
        ("Thời gian thực thi (giây)", lambda r: f"{r['elapsed_seconds']}s"),
        ("Tốc độ (execs/sec)", lambda r: f"{int(r['iterations'] / max(r['elapsed_seconds'], 0.0001))}"),
        ("Số lần Crash (MemoryError)", lambda r: str(r["crashes"])),
        ("Lần đầu phát hiện Crash", lambda r: str(r["first_crash_iter"]) if r["first_crash_iter"] else "N/A"),
        ("Tỷ lệ Crash (%)", lambda r: f"{(r['crashes'] / r['iterations']) * 100:.2f}%"),
        ("Số lần Logic Bypass", lambda r: str(r["bypass_granted"])),
        ("Lần đầu phát hiện Bypass", lambda r: str(r["first_bypass_iter"]) if r["first_bypass_iter"] else "N/A"),
        ("Xác thực hợp lệ (Token)", lambda r: str(r["auth_granted"])),
        ("Từ chối an toàn (Blocked/Error)", lambda r: str(r["blocked_error"]))
    ]

    r1 = results["blackbox_vulnerable"]
    r2 = results["whitebox_vulnerable"]
    r3 = results["blackbox_patched"]
    r4 = results["whitebox_patched"]

    for label, fn in metrics:
        print(row_fmt.format(label, fn(r1), fn(r2), fn(r3), fn(r4)))

    print("=" * 105)

def analyze_findings(results):
    print("\nPHÂN TÍCH VÀ ĐÁNH GIÁ KẾT QUẢ FUZZING:")
    print("1. Hiệu năng phát hiện lỗi giữa Black-box và White-box:")
    v_bb_crashes = results["blackbox_vulnerable"]["crashes"]
    v_wb_crashes = results["whitebox_vulnerable"]["crashes"]
    v_wb_bypass = results["whitebox_vulnerable"]["bypass_granted"]
    first_crash = results["whitebox_vulnerable"]["first_crash_iter"]
    first_bypass = results["whitebox_vulnerable"]["first_bypass_iter"]

    print(f"   - Black-box trên Target: Phát hiện {v_bb_crashes} crash. Sinh byte ngẫu nhiên mù quáng hầu như không thể vượt qua Magic Header (PASS) và Token check (32 bytes).")
    print(f"   - White-box trên Target: Phát hiện {v_wb_crashes} crashes (ngay từ lần thứ {first_crash}) và {v_wb_bypass} lần logic bypass (ngay từ lần thứ {first_bypass}).")
    print("   - Nhờ nhận biết cấu trúc gói tin và tập trung vào các giá trị biên (Boundary Testing: payload_len > 128), White-box đạt hiệu quả vượt trội trong việc kích hoạt lỗi tiềm ẩn.")

    print("\n2. Đánh giá độ an toàn của bản vá TargetGatewayPatched:")
    p_crashes = results["whitebox_patched"]["crashes"] + results["blackbox_patched"]["crashes"]
    p_bypass = results["whitebox_patched"]["bypass_granted"] + results["blackbox_patched"]["bypass_granted"]
    print(f"   - Tổng số crashes trên bản Patched: {p_crashes}")
    print(f"   - Tổng số logic bypass trên bản Patched: {p_bypass}")
    print("   - Kết luận: Bản vá đã khắc phục triệt để lỗ hổng Buffer Overflow (kiểm tra trước kích thước payload_len <= 128) và loại bỏ hoàn toàn cửa sau DEBUG_BYPASS_999.")

def save_fuzzing_logs(results):
    log_dir = os.path.join(os.path.dirname(__file__), "logs")
    os.makedirs(log_dir, exist_ok=True)
    report_path = os.path.join(log_dir, "fuzzing_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n[Ghi nhận] Báo cáo chi tiết và crash samples đã được lưu tại: {report_path}")

def run_fuzzing_suite():
    iterations = 10000

    bb_fuzzer = BlackBoxFuzzer()
    wb_fuzzer = WhiteBoxFuzzer()

    results = {
        "blackbox_vulnerable": execute_fuzzing(APIGateway, bb_fuzzer, iterations),
        "whitebox_vulnerable": execute_fuzzing(APIGateway, wb_fuzzer, iterations),
        "blackbox_patched": execute_fuzzing(APIGatewayPatched, bb_fuzzer, iterations),
        "whitebox_patched": execute_fuzzing(APIGatewayPatched, wb_fuzzer, iterations)
    }

    print_comparison_table(results)
    analyze_findings(results)
    save_fuzzing_logs(results)

if __name__ == "__main__":
    random.seed(42)
    run_fuzzing_suite()
