package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
)

func main() {
	// 简化的测试日志
	logContent := `09:19:54 executing program pair 2:
Program 1:
r0 = open$kccwf(&(0x7f0000000040), 0x2, 0x0)
pwritev2$kccwf(r0, &(0x7f0000000340)=[{&(0x7f0000000080)='h', 0x1}], 0x1, 0x0, 0x0, 0x2)

Program 2:
r0 = open$kccwf(&(0x7f0000000000), 0x0, 0x0)
fstat$kccwf(r0, &(0x7f0000000100))

2025/09/29 09:19:54 proc 2: about to acquire gate ticket`

	// 使用配置文件创建target
	cfg, err := mgrconfig.LoadFile("/home/zzzccc/go-work/syzkaller-old/syzkaller/test/f2fs/test_f2fs.cfg")
	if err != nil {
		log.Fatalf("无法加载配置文件: %v", err)
	}
	target := cfg.Target

	lines := strings.Split(logContent, "\n")
	pairRegex := regexp.MustCompile(`executing program pair (\d+):`)
	
	var currentProgram strings.Builder
	var parsingProgram1 bool
	var parsingProgram2 bool
	var prog1Text, prog2Text string
	
	for i, line := range lines {
		fmt.Printf("Line %d: %q\n", i, line)
		
		// 检查是否开始新的程序对
		if match := pairRegex.FindStringSubmatch(line); match != nil {
			fmt.Printf("  找到程序对: %s\n", match[1])
			continue
		}
		
		// 检查是否开始 Program 1
		if strings.Contains(line, "Program 1:") {
			fmt.Printf("  开始解析 Program 1\n")
			parsingProgram1 = true
			parsingProgram2 = false
			currentProgram.Reset()
			continue
		}
		
		// 检查是否开始 Program 2
		if strings.Contains(line, "Program 2:") {
			fmt.Printf("  开始解析 Program 2\n")
			// 保存 Program 1
			if parsingProgram1 {
				prog1Text = currentProgram.String()
				fmt.Printf("  Program 1 文本: %q\n", prog1Text)
			}
			
			parsingProgram1 = false
			parsingProgram2 = true
			currentProgram.Reset()
			continue
		}
		
		// 检查是否遇到日志行
		if strings.Contains(line, "2025/") {
			fmt.Printf("  遇到日志行，停止解析\n")
			// 保存 Program 2
			if parsingProgram2 {
				prog2Text = currentProgram.String()
				fmt.Printf("  Program 2 文本: %q\n", prog2Text)
			}
			parsingProgram1 = false
			parsingProgram2 = false
			continue
		}
		
		// 如果正在解析程序内容
		if (parsingProgram1 || parsingProgram2) && strings.TrimSpace(line) != "" {
			fmt.Printf("  添加程序行: %q\n", line)
			currentProgram.WriteString(line)
			currentProgram.WriteString("\n")
		}
	}
	
	// 尝试解析程序
	fmt.Printf("\n=== 解析结果 ===\n")
	
	if prog1Text != "" {
		if p, err := target.Deserialize([]byte(prog1Text), prog.NonStrict); err == nil {
			fmt.Printf("Program 1 解析成功:\n%s\n", p.Serialize())
		} else {
			fmt.Printf("Program 1 解析失败: %v\n", err)
		}
	}
	
	if prog2Text != "" {
		if p, err := target.Deserialize([]byte(prog2Text), prog.NonStrict); err == nil {
			fmt.Printf("Program 2 解析成功:\n%s\n", p.Serialize())
		} else {
			fmt.Printf("Program 2 解析失败: %v\n", err)
		}
	}
}