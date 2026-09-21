import sys
import step1_kripke_analysis
import step2_codegen
import step3_static_testing
import step4_dynamic_testing

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

if sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

def run_pipeline():
    print("\n" + "#" * 90)
    print("QUY TRÌNH ĐÁNH GIÁ AN TOÀN END-TO-END CHO MODULE PARSERS AUTHENTICATION GATEWAY")
    print("THEO CHUẨN ĐẶC TẢ HÌNH THỨC KRIPKE VÀ CHU TRÌNH: SINH MÃ -> KIỂM THỬ TĨNH -> KIỂM THỬ ĐỘNG")
    print("#" * 90 + "\n")

    step1_kripke_analysis.run_kripke_analysis()
    print("\n")
    step2_codegen.run_code_generation()
    print("\n")
    step3_static_testing.run_static_testing()
    print("\n")
    step4_dynamic_testing.run_dynamic_testing()

    print("\n" + "#" * 90)
    print("HOÀN TẤT THÀNH CÔNG TOÀN BỘ QUY TRÌNH ĐÁNH GIÁ AN TOÀN END-TO-END CHO GATEWAY")
    print("#" * 90 + "\n")

if __name__ == "__main__":
    run_pipeline()
