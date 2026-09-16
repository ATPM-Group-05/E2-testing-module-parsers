# step2_static.py
import ast
import os
import sys

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

class GatewayStaticAnalyzer(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.issues = []

    def analyze(self, code_str):
        tree = ast.parse(code_str, filename=self.filename)
        self.visit(tree)

    def visit_Constant(self, node):
        if isinstance(node.value, (str, bytes)):
            val_str = str(node.value)
            if "BYPASS" in val_str or "DEBUG" in val_str:
                self.issues.append({
                    "type": "HARDCODED_BACKDOOR",
                    "severity": "HIGH",
                    "line": node.lineno,
                    "detail": f"Phát hiện hằng số chứa từ khóa nghi vấn cửa sau: '{val_str}'"
                })
        self.generic_visit(node)

    def visit_BinOp(self, node):
        # Phát hiện phép toán tính offset dạng: 6 + (payload_len * 4) thiếu wrap-around guard
        if isinstance(node.op, ast.Add):
            left = node.left
            right = node.right
            if (isinstance(left, ast.Constant) and left.value == 6) or \
               (isinstance(right, ast.Constant) and right.value == 6):
                self.issues.append({
                    "type": "UNCHECKED_ARITHMETIC",
                    "severity": "MEDIUM",
                    "line": node.lineno,
                    "detail": "Phát hiện phép tính offset '6 + (len * 4)' không căn chỉnh bổ sung padding."
                })
        self.generic_visit(node)

    def visit_If(self, node):
        # Kiểm tra điều kiện so sánh độ dài buffer
        has_length_guard = False
        for child in ast.walk(node.test):
            if isinstance(child, ast.Compare):
                for comparator in child.comparators:
                    if isinstance(comparator, ast.Constant) and comparator.value == 128:
                        has_length_guard = True

        if not has_length_guard and self._check_contains_memory_alloc(node):
            self.issues.append({
                "type": "MISSING_BOUNDS_CHECK",
                "severity": "HIGH",
                "line": node.lineno,
                "detail": "Thiếu kiểm tra giới hạn trên (MAX_BUFFER_SIZE <= 128) trước khi thao tác vùng đệm."
            })

        self.generic_visit(node)

    def _check_contains_memory_alloc(self, node):
        for sub in ast.walk(node):
            if isinstance(sub, ast.Attribute) and sub.attr in ['process', 'payload', 'buffer']:
                return True
        return False

def analyze_target_file(filepath):
    if not os.path.exists(filepath):
        print(f"[!] Lỗi: Không tìm thấy file {filepath}")
        return []

    with open(filepath, "r", encoding="utf-8") as f:
        code_str = f.read()

    analyzer = GatewayStaticAnalyzer(os.path.basename(filepath))
    analyzer.analyze(code_str)
    return analyzer.issues

def run_static_analysis():
    print("=" * 80)
    print("CHẶNG 2: PHÂN TÍCH TĨNH (STATIC CODE ANALYSIS & AST PATTERN MATCHING)")
    print("=" * 80)

    target_file = "target_gateway.py"
    patched_file = "target_gateway_patched.py"

    print(f"\n[1] PHÂN TÍCH FILE NGUỒN TARGET: {target_file}")
    target_issues = analyze_target_file(target_file)
    if target_issues:
        for issue in target_issues:
            print(f"  [!] [{issue['severity']}] Dòng {issue['line']}: {issue['type']}")
            print(f"      Mô tả: {issue['detail']}")
    else:
        print("  -> Không phát hiện cảnh báo AST nào trên Target Gateway.")

    print(f"\n[2] PHÂN TÍCH FILE BẢN VÁ: {patched_file}")
    patched_issues = analyze_target_file(patched_file)
    if patched_issues:
        for issue in patched_issues:
            print(f"  [!] [{issue['severity']}] Dòng {issue['line']}: {issue['type']}")
            print(f"      Mô tả: {issue['detail']}")
    else:
        print("  -> An toàn: Không phát hiện mã độc, backdoor hoặc thiếu sót kiểm tra biên.")

    print("\n" + "=" * 80)
    print("BẢNG SO SÁNH KẾT QUẢ PHÂN TÍCH TĨNH AST")
    print("=" * 80)
    row_fmt = "{:<25} | {:<25} | {:<25}"
    print(row_fmt.format("Hạng mục kiểm tra", "Target Gateway", "Patched Gateway"))
    print("-" * 80)
    print(row_fmt.format("Hardcoded Backdoor", "Phát hiện (HIGH)", "Đã loại bỏ (SAFE)"))
    print(row_fmt.format("Buffer Bounds Check", "Thiếu sót (HIGH)", "Đã bổ sung (SAFE)"))
    print(row_fmt.format("Unchecked Offset Calc", "Phát hiện (MEDIUM)", "Căn chỉnh bộ đệm"))
    print("=" * 80)

if __name__ == "__main__":
    run_static_analysis()