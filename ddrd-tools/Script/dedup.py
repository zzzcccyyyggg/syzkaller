import os
import re

def extract_unique_reports(text):
    """提取所有 Data Race 报告，按无序 VarName 对去重，返回唯一报告映射"""
    report_sections = text.split("=================END==============")
    seen_pairs = set()
    unique_reports = {}

    for section in report_sections:
        if "Kernel panic: ============ DATARACE ============" not in section:
            continue  # 跳过噪声或非 Data Race 报告
        varnames = re.findall(r'VarName (\d+)', section)
        if len(varnames) >= 2:
            v1, v2 = int(varnames[0]), int(varnames[1])
            pair = tuple(sorted((v1, v2)))  # 无序对
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                full_report = section.strip() + "\n=================END==============\n"
                unique_reports[pair] = full_report
    return unique_reports

def process_folder(folder_path):
    """递归处理所有 report 文件，返回去重后的 VarName 对及完整报告"""
    dedup_reports = {}

    for root, _, files in os.walk(folder_path):
        for filename in files:
            if not filename.endswith(".txt") and not filename.startswith("report"):
                continue  # 忽略非报告文件
            file_path = os.path.join(root, filename)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                    file_reports = extract_unique_reports(text)
                    for pair, report in file_reports.items():
                        if pair not in dedup_reports:
                            dedup_reports[pair] = report
            except Exception as e:
                print(f"无法读取文件 {file_path}：{e}")
    return dedup_reports

def format_varname_set(pairs):
    """将所有 varname 对格式化为 {a1ULL,a2ULL,...}; 格式"""
    flat_list = [f"{v}ULL" for pair in sorted(pairs) for v in pair]
    return "{" + ",".join(flat_list) + "};"

def main():
    import sys
    if len(sys.argv) != 2:
        print("用法: python3 dedup_varnames_from_folder.py <report_folder>")
        return

    folder_path = sys.argv[1]
    if not os.path.isdir(folder_path):
        print(f"错误：'{folder_path}' 不是有效的文件夹路径。")
        return

    dedup_reports = process_folder(folder_path)

    output_path = "deduped_reports.txt"
    with open(output_path, "w", encoding="utf-8") as f:
        for pair in sorted(dedup_reports):
            f.write(dedup_reports[pair])
            f.write("\n")

    print(f"\n共写入去重后的 Data Race 报告 {len(dedup_reports)} 个 到文件：{output_path}")

    # 打印所有 VarName 对集合格式
    varname_set_str = format_varname_set(dedup_reports.keys())
    print("\n所有 VarName 对（格式 {v1,v2,v3,...}; ）如下：")
    print(varname_set_str)

if __name__ == "__main__":
    main()
