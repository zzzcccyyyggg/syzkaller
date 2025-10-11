package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
)

// PairLogEntry 描述一对程序的日志条目
type PairLogEntry struct {
	PairID   int        // pair ID (如 2, 4, 5 等)
	Proc     int        // 进程ID
	Program1 *prog.Prog // 第一个程序
	Program2 *prog.Prog // 第二个程序
	Start    int        // 在日志中的开始位置
	End      int        // 在日志中的结束位置
}

// ParsePairLog 解析包含程序对的日志
func ParsePairLog(target *prog.Target, data []byte) []*PairLogEntry {
	var entries []*PairLogEntry
	
	lines := strings.Split(string(data), "\n")
	
	// 正则表达式匹配 "executing program pair X:"
	pairRegex := regexp.MustCompile(`executing program pair (\d+):`)
	
	var currentEntry *PairLogEntry
	var currentProgram strings.Builder
	var parsingProgram1 bool
	var parsingProgram2 bool
	
	for i, line := range lines {
		
		// 检查是否开始新的程序对
		if match := pairRegex.FindStringSubmatch(line); match != nil {
			// 如果之前有未完成的条目，先保存它
			if currentEntry != nil {
				entries = append(entries, currentEntry)
			}
			
			// 创建新的条目
			var pairID int
			fmt.Sscanf(match[1], "%d", &pairID)
			currentEntry = &PairLogEntry{
				PairID: pairID,
				Start:  i,
			}
			continue
		}
		
		// 检查是否开始 Program 1
		if strings.Contains(line, "Program 1:") {
			parsingProgram1 = true
			parsingProgram2 = false
			currentProgram.Reset()
			continue
		}
		
		// 检查是否开始 Program 2
		if strings.Contains(line, "Program 2:") {
			// 保存 Program 1
			if currentEntry != nil && parsingProgram1 {
				prog1Text := currentProgram.String()
				if p, err := target.Deserialize([]byte(prog1Text), prog.NonStrict); err == nil {
					currentEntry.Program1 = p
				}
			}
			
			parsingProgram1 = false
			parsingProgram2 = true
			currentProgram.Reset()
			continue
		}
		
		// 检查是否遇到日志行（以时间戳开头或内核日志格式）
		if strings.HasPrefix(line, "2025/") || strings.HasPrefix(strings.TrimSpace(line), "[") {
			// 如果正在解析 Program 2，保存它
			if currentEntry != nil && parsingProgram2 {
				prog2Text := currentProgram.String()
				if p, err := target.Deserialize([]byte(prog2Text), prog.NonStrict); err == nil {
					currentEntry.Program2 = p
				}
				currentEntry.End = i
			}
			parsingProgram1 = false
			parsingProgram2 = false
			continue
		}
		
		// 如果正在解析程序内容，添加到当前程序
		if (parsingProgram1 || parsingProgram2) && strings.TrimSpace(line) != "" {
			currentProgram.WriteString(line)
			currentProgram.WriteString("\n")
		}
	}
	
	// 处理最后一个条目
	if currentEntry != nil {
		if parsingProgram2 && currentProgram.Len() > 0 {
			prog2Text := currentProgram.String()
			if p, err := target.Deserialize([]byte(prog2Text), prog.NonStrict); err == nil {
				currentEntry.Program2 = p
			}
		}
		currentEntry.End = len(lines)
		entries = append(entries, currentEntry)
	}
	
	return entries
}

func main() {
	// 示例日志内容
	logContent := `[  171.704978] [CHECKER_MONITOR] checker_monitor: TURN_OFF_KCCWF
2025/09/29 09:19:54 proc 2: pair execution failed: executor 2: failed to read pair completion: EOF
2025/09/29 09:19:54 proc 2: released gate ticket=29 (env=0xc000098510)
09:19:54 executing program pair 2:
Program 1:
r0 = open$kccwf(&(0x7f0000000040), 0x2, 0x0)
pwritev2$kccwf(r0, &(0x7f0000000340)=[{&(0x7f0000000080)='h', 0x1}], 0x1, 0x0, 0x0, 0x2)

Program 2:
r0 = open$kccwf(&(0x7f0000000000), 0x0, 0x0)
fstat$kccwf(r0, &(0x7f0000000100))

2025/09/29 09:19:54 proc 2: about to acquire gate ticket (env=0xc000098510)
2025/09/29 09:19:54 proc 2: acquired gate ticket=12 (env=0xc000098510)
09:19:55 executing program pair 4:
Program 1:
r0 = open$kccwf(&(0x7f0000000040), 0x2, 0x0)
pwritev2$kccwf(r0, &(0x7f0000000340)=[{&(0x7f0000000080)='h', 0x1}], 0x1, 0x0, 0x0, 0x2)

Program 2:
r0 = open$kccwf(&(0x7f0000001b80), 0x0, 0x0)
ioctl$FITRIM(r0, 0xc0185879, &(0x7f0000000080)={0x0, 0xffffffff00000001, 0xeb54})

2025/09/29 09:19:55 proc 4: about to acquire gate ticket (env=0xc000098630)
09:19:55 executing program pair 0:
Program 1:
r0 = open$kccwf(&(0x7f0000000040), 0x2, 0x0)
pwritev2$kccwf(r0, &(0x7f0000000340)=[{&(0x7f0000000080)='h', 0x1}], 0x1, 0x0, 0x0, 0x2)

Program 2:
fdatasync$kccwf(0xffffffffffffffff)
dup2$kccwf(0xffffffffffffffff, 0xffffffffffffffff)
r0 = open$kccwf(&(0x7f0000000280), 0x44902, 0x0)
r1 = dup$kccwf(r0)
sendfile$kccwf(r1, r1, 0x0, 0x7fffffffffffffff)

2025/09/29 09:19:55 proc 0: about to acquire gate ticket (env=0xc0000982d0)`

	// 尝试加载配置来获取target
	var target *prog.Target
	if cfg, err := mgrconfig.LoadFile("/home/zzzccc/go-work/syzkaller-old/syzkaller/test/f2fs/test_f2fs.cfg"); err == nil {
		target = cfg.Target
		log.Printf("成功加载配置文件，target: %s/%s", target.OS, target.Arch)
	} else {
		log.Printf("无法加载配置文件，尝试创建默认Linux target: %v", err)
		// 创建默认的Linux target
		if t, err := prog.GetTarget("linux", "amd64"); err == nil {
			target = t
		} else {
			log.Fatalf("无法创建target: %v", err)
		}
	}

	// 解析程序对日志
	entries := ParsePairLog(target, []byte(logContent))
	
	fmt.Printf("=== 从程序对日志解析出的结果 ===\n")
	fmt.Printf("找到 %d 个程序对\n\n", len(entries))
	
	for i, entry := range entries {
		fmt.Printf("--- 程序对 %d (PairID %d) ---\n", i+1, entry.PairID)
		
		if entry.Program1 != nil {
			fmt.Printf("Program 1 (标准格式):\n%s\n", entry.Program1.Serialize())
			fmt.Printf("Program 1 系统调用:\n")
			for j, call := range entry.Program1.Calls {
				fmt.Printf("  %d. %s\n", j+1, call.Meta.Name)
			}
		} else {
			fmt.Printf("Program 1: 解析失败\n")
		}
		
		fmt.Printf("\n")
		
		if entry.Program2 != nil {
			fmt.Printf("Program 2 (标准格式):\n%s\n", entry.Program2.Serialize())
			fmt.Printf("Program 2 系统调用:\n")
			for j, call := range entry.Program2.Calls {
				fmt.Printf("  %d. %s\n", j+1, call.Meta.Name)
			}
		} else {
			fmt.Printf("Program 2: 解析失败\n")
		}
		
		fmt.Printf("\n" + strings.Repeat("=", 60) + "\n\n")
	}
	
	// 显示最终格式的总结
	fmt.Printf("=== 最终提取的程序对格式 ===\n")
	for _, entry := range entries {
		fmt.Printf("PairID: %d\n", entry.PairID)
		if entry.Program1 != nil && entry.Program2 != nil {
			fmt.Printf("Pair Programs:\n")
			fmt.Printf("Program1:\n%s\nProgram2:\n%s\n", 
				entry.Program1.Serialize(), 
				entry.Program2.Serialize())
		}
		fmt.Printf("---\n")
	}
}