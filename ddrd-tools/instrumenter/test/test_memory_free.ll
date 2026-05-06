; 测试内存释放函数插桩的LLVM IR文件
; ModuleID = 'test_memory_free.c'
source_filename = "test_memory_free.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; 声明外部函数
declare i8* @kmalloc(i64, i32) #0
declare void @kfree(i8*) #0
declare i8* @kvmalloc(i64, i32) #0
declare void @kvfree(i8*) #0
declare i8* @kmem_cache_alloc(%struct.kmem_cache*, i32) #0
declare void @kmem_cache_free(%struct.kmem_cache*, i8*) #0

%struct.kmem_cache = type opaque

; 测试函数：使用kfree
define void @test_kfree() #0 !dbg !6 {
entry:
  %ptr = call i8* @kmalloc(i64 100, i32 208), !dbg !10
  call void @kfree(i8* %ptr), !dbg !11
  ret void, !dbg !12
}

; 测试函数：使用kvfree
define void @test_kvfree() #0 !dbg !13 {
entry:
  %ptr = call i8* @kvmalloc(i64 200, i32 208), !dbg !14
  call void @kvfree(i8* %ptr), !dbg !15
  ret void, !dbg !16
}

; 测试函数：使用kmem_cache_free
define void @test_kmem_cache_free(%struct.kmem_cache* %cache) #0 !dbg !17 {
entry:
  %ptr = call i8* @kmem_cache_alloc(%struct.kmem_cache* %cache, i32 208), !dbg !18
  call void @kmem_cache_free(%struct.kmem_cache* %cache, i8* %ptr), !dbg !19
  ret void, !dbg !20
}

attributes #0 = { nounwind }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3, !4}
!llvm.ident = !{!5}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "clang version 18.1.3", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, enums: !2)
!1 = !DIFile(filename: "test_memory_free.c", directory: "/home/zzzccc/DDRD/instrumenter/test")
!2 = !{}
!3 = !{i32 2, !"Dwarf Version", i32 4}
!4 = !{i32 2, !"Debug Info Version", i32 3}
!5 = !{!"clang version 18.1.3"}
!6 = distinct !DISubprogram(name: "test_kfree", scope: !1, file: !1, line: 10, type: !7, scopeLine: 10, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!7 = !DISubroutineType(types: !8)
!8 = !{!9}
!9 = !DIBasicType(name: "void", encoding: DW_ATE_void)
!10 = !DILocation(line: 11, column: 17, scope: !6)
!11 = !DILocation(line: 12, column: 5, scope: !6)
!12 = !DILocation(line: 13, column: 1, scope: !6)
!13 = distinct !DISubprogram(name: "test_kvfree", scope: !1, file: !1, line: 15, type: !7, scopeLine: 15, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!14 = !DILocation(line: 16, column: 17, scope: !13)
!15 = !DILocation(line: 17, column: 5, scope: !13)
!16 = !DILocation(line: 18, column: 1, scope: !13)
!17 = distinct !DISubprogram(name: "test_kmem_cache_free", scope: !1, file: !1, line: 20, type: !7, scopeLine: 20, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!18 = !DILocation(line: 21, column: 17, scope: !17)
!19 = !DILocation(line: 22, column: 5, scope: !17)
!20 = !DILocation(line: 23, column: 1, scope: !17)
