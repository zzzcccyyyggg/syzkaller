def hex_to_signed_64(hex_str):
    # 去掉前缀 0x（如果有）
    if hex_str.startswith("0x") or hex_str.startswith("0X"):
        hex_str = hex_str[2:]
    # 转为无符号整数
    val = int(hex_str, 16)
    # 如果大于有符号 64 位最大值，则视为负数
    if val >= 2**63:
        val -= 2**64
    return val

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("用法: python hex_to_signed64.py <hex_value>")
        print("示例: python hex_to_signed64.py 0x2e3508d72022cec3")
        sys.exit(1)

    hex_input = sys.argv[1]
    result = hex_to_signed_64(hex_input)
    print(f"有符号 64 位整数: {result}")
