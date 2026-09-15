# Quy trình Đánh giá An toàn End-to-End cho Module API Request Parser & Authentication Gateway

Dự án Bài tập lớn học phần **An toàn phần mềm** - Đánh giá an toàn toàn diện 4 chương qua `softsec-toolkit` và `Z3 Solver`.

## 📁 Cấu trúc Mã nguồn
- `target_gateway.py`: Module mục tiêu chứa các lỗ hổng cài đặt có chủ đích (Logic Bypass, Memory, Integer Overflow).
- `target_gateway_patched.py`: Module mục tiêu sau khi đã được khắc phục lỗ hổng.
- `step1_bmc.py`: (Chương 1) Kiểm chứng mô hình Kripke và Bounded Model Checking (BMC).
- `step2_static.py`: (Chương 2) Phân tích tĩnh nhận diện các mẫu code không an toàn.
- `step3_smt.py`: (Chương 3) Kiểm chứng hình thức điều kiện số học / Alignment bằng Z3 SMT Solver.
- `step4_fuzzing.py`: (Chương 4) Kiểm thử động Fuzzing (So sánh Black-box vs White-box).

## 🚀 Hướng dẫn Chạy
1. Cài đặt môi trường:
   ```bash
   pip install -r requirements.txt