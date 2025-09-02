package main

import (
	"fmt"
	"unsafe"

	"github.com/google/syzkaller/pkg/ddrd"
)

func main() {
	fmt.Printf("Go MayRacePair struct size: %d bytes\n", unsafe.Sizeof(ddrd.MayRacePair{}))

	// Show field offsets to understand layout
	var pair ddrd.MayRacePair
	fmt.Printf("Field offsets:\n")
	fmt.Printf("  Syscall1Idx: %d\n", unsafe.Offsetof(pair.Syscall1Idx))
	fmt.Printf("  Syscall2Idx: %d\n", unsafe.Offsetof(pair.Syscall2Idx))
	fmt.Printf("  Syscall1Num: %d\n", unsafe.Offsetof(pair.Syscall1Num))
	fmt.Printf("  Syscall2Num: %d\n", unsafe.Offsetof(pair.Syscall2Num))
	fmt.Printf("  VarName1: %d\n", unsafe.Offsetof(pair.VarName1))
	fmt.Printf("  VarName2: %d\n", unsafe.Offsetof(pair.VarName2))
	fmt.Printf("  CallStack1: %d\n", unsafe.Offsetof(pair.CallStack1))
	fmt.Printf("  CallStack2: %d\n", unsafe.Offsetof(pair.CallStack2))
	fmt.Printf("  Sn1: %d\n", unsafe.Offsetof(pair.Sn1))
	fmt.Printf("  Sn2: %d\n", unsafe.Offsetof(pair.Sn2))
	fmt.Printf("  Signal: %d\n", unsafe.Offsetof(pair.Signal))
	fmt.Printf("  LockType: %d\n", unsafe.Offsetof(pair.LockType))
	fmt.Printf("  AccessType1: %d\n", unsafe.Offsetof(pair.AccessType1))
	fmt.Printf("  AccessType2: %d\n", unsafe.Offsetof(pair.AccessType2))
	fmt.Printf("  TimeDiff: %d\n", unsafe.Offsetof(pair.TimeDiff))

	fmt.Printf("Total size: %d bytes\n", unsafe.Sizeof(pair))
}
