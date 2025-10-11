package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/google/syzkaller/pkg/mgrconfig"
)

func main() {
	// 示例日志内容 - 就是你提供的那个
	logContent := `23:51:03 executing program 10:
mknodat$kccwf(0xffffffffffffff9c, &(0x7f0000000040), 0x0, 0x0)
r0 = dup2$kccwf(0xffffffffffffffff, 0xffffffffffffffff)
name_to_handle_at$kccwf(0xffffffffffffff9c, &(0x7f0000000080), &(0x7f00000000c0)=@reiserfs_5={0x14, 0x5, {0xc, 0x8, 0x37, 0x80000000, 0x7697}}, &(0x7f0000000100), 0x1000)
ioctl$F2FS_IOC_MOVE_RANGE(r0, 0xc020f509, &(0x7f0000000000)={0xffffffffffffffff, 0x4, 0x5, 0x20})

23:51:03 executing program 1:
r0 = open$kccwf(&(0x7f0000000000), 0x0, 0x0)
r1 = open$kccwf(&(0x7f0000000000), 0x0, 0x0)
dup$kccwf(r1) (async)
r2 = dup$kccwf(r1)
dup$kccwf(r2)
r3 = dup2$kccwf(r1, r2)
open$kccwf(&(0x7f0000000000), 0x0, 0x0) (async)
r4 = open$kccwf(&(0x7f0000000000), 0x0, 0x0)
ioctl$F2FS_IOC_GARBAGE_COLLECT_RANGE(r4, 0x8004f51a, &(0x7f0000000040))
fsetxattr$kccwf(r0, &(0x7f00000003c0), &(0x7f0000000400)="e0e053f0a57bfa0f989074093ef1f9fa4dcce60ade49bf8221a9bb2a3dcf4eca6a44fc69319b4f35b9498227c3fdda14c50b4bfeb10b677ad9283c19661c7a424c87699e030094429cc1422ed1dfe202635d71935176affa168b6294468bc4735eca8b0c106321a109a5ae41bfc62c4fc2b30e3de7bde52768521ced2f611ef53fef20ca7725250677f6fb7f76e3c3a8f48a3922cfdbefb2f8c62d083d3674115cc5aba2d08f146767b57c3426d3f038", 0xb0, 0x20) (async)
fsetxattr$kccwf(r0, &(0x7f00000003c0), &(0x7f0000000400)="e0e053f0a57bfa0f989074093ef1f9fa4dcce60ade49bf8221a9bb2a3dcf4eca6a44fc69319b4f35b9498227c3fdda14c50b4bfeb10b677ad9283c19661c7a424c87699e030094429cc1422ed1dfe202635d71935176affa168b6294468bc4735eca8b0c106321a109a5ae41bfc62c4fc2b30e3de7bde52768521ced2f611ef53fef20ca7725250677f6fb7f76e3c3a8f48a3922cfdbefb2f8c62d083d3674115cc5aba2d08f146767b57c3426d3f038", 0xb0, 0x20)
dup2$kccwf(r3, r4)
r5 = open$kccwf(&(0x7f0000000040), 0x121041, 0x0)
dup2$kccwf(0xffffffffffffffff, r3) (async)
r6 = dup2$kccwf(0xffffffffffffffff, r3)
dup$kccwf(r6)`

	// 加载默认配置来获取target
	cfg, err := mgrconfig.LoadFile("example_config_combined.json")
	if err != nil {
		log.Printf("无法加载配置文件，使用默认Linux target: %v", err)
		// 如果没有配置文件，我们需要手动创建target，这里简化处理
		return
	}

	// 解析日志
	entries := cfg.Target.ParseLog([]byte(logContent))
	
	fmt.Printf("=== 从日志解析出的程序 ===\n")
	fmt.Printf("找到 %d 个程序执行记录\n\n", len(entries))
	
	for i, entry := range entries {
		fmt.Printf("--- 程序 %d (Proc %d) ---\n", i+1, entry.Proc)
		if entry.P != nil {
			// 显示原始序列化格式
			fmt.Printf("标准序列化格式:\n%s\n", entry.P.Serialize())
			
			// 显示详细序列化格式  
			fmt.Printf("\n详细序列化格式:\n%s\n", entry.P.SerializeVerbose())
			
			// 显示程序信息
			fmt.Printf("\n程序信息:\n")
			fmt.Printf("- 系统调用数量: %d\n", len(entry.P.Calls))
			for j, call := range entry.P.Calls {
				fmt.Printf("  %d. %s\n", j+1, call.Meta.Name)
			}
		}
		fmt.Printf("\n" + strings.Repeat("=", 50) + "\n\n")
	}
}