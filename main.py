import sys
import step1_bmc
import step2_static
import step3_smt
import step4_fuzzing

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

def run_all_stages():
    print("\n" + "#" * 80)
    print("QUY TRÌNH ĐÁNH GIÁ AN TOÀN TOÀN DIỆN END-TO-END CHO API GATEWAY")
    print("#" * 80 + "\n")

    step1_bmc.run_bmc_verification()
    print("\n")
    step2_static.run_static_analysis()
    print("\n")
    step3_smt.run_smt_verification()
    print("\n")
    step4_fuzzing.run_fuzzing_suite()

    print("\n" + "#" * 80)
    print("HOÀN TẤT TOÀN BỘ 4 CHẶNG ĐÁNH GIÁ AN TOÀN PHẦN MỀM THÀNH CÔNG")
    print("#" * 80 + "\n")

if __name__ == "__main__":
    run_all_stages()
