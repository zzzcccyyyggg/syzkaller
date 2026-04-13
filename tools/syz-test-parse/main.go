package main

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
)

func main() {
	cfg, err := mgrconfig.LoadFile("exp/bt-stack/exp-validate.cfg")
	if err != nil {
		fmt.Printf("load config: %v\n", err)
		return
	}
	target := cfg.Target

	p1text := "r0 = syz_init_net_socket$bt_sco(0x1f, 0x5, 0x2)\n"
	p1, err := target.Deserialize([]byte(p1text), prog.NonStrict)
	if err != nil {
		fmt.Printf("test1 FAIL: %v\n", err)
	} else {
		fmt.Printf("test1 OK: %d calls\n%s\n", len(p1.Calls), string(p1.Serialize()))
	}

	for name, sc := range target.SyscallMap {
		if strings.Contains(name, "bt_sco") || strings.Contains(name, "$sco") {
			fmt.Printf("  syscall: %s (ID=%d)\n", sc.Name, sc.ID)
		}
	}

	p2text := "r0 = syz_init_net_socket$bt_sco(0x1f, 0x5, 0x2)\nbind$bt_sco(r0, &(0x7f0000000000)={0x1f, @any}, 0x8)\n"
	p2, err := target.Deserialize([]byte(p2text), prog.NonStrict)
	if err != nil {
		fmt.Printf("test2 FAIL: %v\n", err)
	} else {
		fmt.Printf("test2 OK: %d calls\n%s\n", len(p2.Calls), string(p2.Serialize()))
	}

	p3text := "r0 = syz_init_net_socket$bt_sco(0x1f, 0x5, 0x2)\nbind$bt_sco(r0, &(0x7f0000000000)={0x1f, @any}, 0x8)\nconnect$bt_sco(r0, &(0x7f0000000040)={0x1f, @fixed={0x10}}, 0x8) (async)\nconnect$bt_sco(r0, &(0x7f0000000080)={0x1f, @fixed={0x10}}, 0x8) (async)\n"
	p3, err := target.Deserialize([]byte(p3text), prog.NonStrict)
	if err != nil {
		fmt.Printf("test3 FAIL: %v\n", err)
	} else {
		fmt.Printf("test3 OK: %d calls\n%s\n", len(p3.Calls), string(p3.Serialize()))
	}
}
