package main

import (
	"fmt"
	"unsafe"

	"github.com/google/syzkaller/pkg/ddrd"
)

func main() {
	var example ddrd.MayRacePair

	fmt.Printf("sizeof(MayRacePair) = %d bytes\n", unsafe.Sizeof(example))
	fmt.Printf("Go struct offset analysis:\n")
	fmt.Printf("  Syscall1Idx offset: %d\n", unsafe.Offsetof(example.Syscall1Idx))
	fmt.Printf("  Syscall2Idx offset: %d\n", unsafe.Offsetof(example.Syscall2Idx))
	fmt.Printf("  Syscall1Num offset: %d\n", unsafe.Offsetof(example.Syscall1Num))
	fmt.Printf("  Syscall2Num offset: %d\n", unsafe.Offsetof(example.Syscall2Num))
	fmt.Printf("  VarName1 offset: %d\n", unsafe.Offsetof(example.VarName1))
	fmt.Printf("  VarName2 offset: %d\n", unsafe.Offsetof(example.VarName2))
	fmt.Printf("  CallStack1 offset: %d\n", unsafe.Offsetof(example.CallStack1))
	fmt.Printf("  CallStack2 offset: %d\n", unsafe.Offsetof(example.CallStack2))
	fmt.Printf("  Sn1 offset: %d\n", unsafe.Offsetof(example.Sn1))
	fmt.Printf("  Sn2 offset: %d\n", unsafe.Offsetof(example.Sn2))
	fmt.Printf("  Signal offset: %d\n", unsafe.Offsetof(example.Signal))
	fmt.Printf("  LockType offset: %d\n", unsafe.Offsetof(example.LockType))
	fmt.Printf("  AccessType1 offset: %d\n", unsafe.Offsetof(example.AccessType1))
	fmt.Printf("  AccessType2 offset: %d\n", unsafe.Offsetof(example.AccessType2))
	fmt.Printf("  TimeDiff offset: %d\n", unsafe.Offsetof(example.TimeDiff))
}
