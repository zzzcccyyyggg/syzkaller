# syzlang 参数填充与规则总览（含 filesystem/filename/glob）

本文专门回答两个问题：
1. `string[filesystem]` / `filename` 是如何被填充的？
2. syzlang 的类型规则在什么位置生效，尤其是 glob/“类似正则”能力。

---

## 1. 从描述文件到运行时值：总链路

1. 在 `sys/linux/*.txt` 写 syscall 描述（类型、flags、resource、struct/union 等）。
2. `make generate` 后，类型进入 `prog` 的类型系统（`*Type`）。
3. 程序生成阶段按类型分派到 `prog/rand.go` 的 `generate` 逻辑。
4. 生成出来的参数再被序列化为 corpus 文本（`prog/encoding.go`）。

核心分派点：
- `prog/rand.go`：`func (a *BufferType) generate(...)`
- `prog/rand.go`：`func (a *ResourceType) generate(...)`
- `prog/rand.go`：`func (a *IntType) generate(...)` 等

---

## 2. 你关心的重点：filesystem 和 filename

## 2.1 `string[filesystem]` 如何填充

以你看的 `sys/linux/filesystem.txt` 为例：
- syscall 参数：`fsopen(type ptr[in, string[filesystem]], ...)`
- 字符串集合定义：
  `filesystem = "sysfs", "rootfs", "ramfs", "tmpfs", ...`

运行时行为：
- 这是 `BufferString` 类型，`Values` 会带上 `filesystem` 这组候选值。
- 在 `prog/rand.go` 的 `randString(...)` 中：
  - 如果 `len(t.Values) != 0`，就从候选集合里随机挑一个。

也就是说：
- `string[filesystem]` 不是“自由随机字节串”，而是“从定义好的字符串白名单里选一个”。

## 2.2 `filename` 如何填充

`filename` 本质是内建别名：
- 在语法文档中等价于 `type filename string[filename]`

运行时行为在 `prog/rand.go`：
- `BufferType.generate` 遇到 `BufferFilename` -> 调 `r.filename(...)`
- `filename(...)` 再调 `filenameImpl(...)` 生成名字

`filenameImpl(...)` 的典型策略：
- 小概率返回特殊值（`""` 或 `"."`）
- 否则优先生成新路径，如 `./file0`, `./file1`, ...
- 也会在已有文件集合里复用已有路径

文件集合来自程序分析阶段：
- `prog/analysis.go` 会扫描已有参数，把 `BufferFilename` 输入收集到 `s.files`
- 这样后续生成能“复用已有文件名”形成更真实的依赖链

安全约束：
- `escapingFilename(...)` 禁止逃逸（绝对路径或 `..` 路径）。

---

## 3. glob、正则与模式匹配：到底支持什么

## 3.1 `glob[...]` 是什么

示例（`sys/linux/sys.txt`）：
- `openat$sysfs(... dir ptr[in, glob["/sys/**/*:-/sys/power/state"]], ...)`

语义：
- `glob` 不是 regex（正则表达式），而是文件路径通配模式。
- 支持 include/exclude：`A:B:-C` 表示包含 A/B，排除 C。

## 3.2 glob 在哪里“展开成具体值”

关键代码：
- `prog/target.go`
  - `RequiredGlobs()`：收集所有需要探测的 pattern
  - `UpdateGlobs(...)`：把 pattern 对应的真实文件列表写回 `BufferType.Values`
  - `populateGlob(...)`：处理 include/exclude 合并
- `pkg/vminfo/syscalls.go`
  - 通过 executor 发起 glob 请求（`RequestTypeGlob`）
  - 收到目标机文件列表后调用 `target.UpdateGlobs(globs)`

之后在生成时：
- `BufferGlob` 也走 `randString(...)`，即从 `Values` 中随机选一个真实路径。

结论：
- syzlang 的 `glob[...]` 依赖目标机实际文件系统探测结果，不是纯静态字面量。

## 3.3 syzlang 有 regex 类型吗？

- 当前没有独立的 regex 参数类型。
- 路径匹配主要是 `glob[...]`。
- 条件表达式里也不是 regex，而是整型表达式（`==`, `!=`, `&`, `||`）。

---

## 4. 常见类型的“填充规则 + 实现位置”速查

## 4.1 数值类

- `const[...]`
  - 规则：固定常量
  - 实现：`prog/rand.go` `ConstType.generate`（直接返回 `a.Val`）

- `int8/int16/int32/int64/intptr`、范围 `int32[0:100]`
  - 规则：随机整数；若有范围/对齐则按范围生成
  - 实现：`IntType.generate` + `randInt` + `randRangeInt`

- `flags[...]`
  - 规则：从 flags 集合中选择；bitmask 时可组合
  - 实现：`FlagsType.generate` -> `flags(...)`

- `proc[start, per_proc, base]`
  - 规则：按 executor 维度分片值域（避免实例间冲突）
  - 实现：`ProcType.generate`

## 4.2 内存/缓冲区类

- `string[...]` / `stringnoz[...]`
  - 规则：有 `Values` 就从集合选；否则随机字节串（可带/不带 `\x00`）
  - 实现：`randString(...)`

- `filename`
  - 规则：生成/复用受限文件名
  - 实现：`filename(...)` + `filenameImpl(...)`

- `glob[...]`
  - 规则：先目标机展开，再从候选值随机选
  - 实现：`target.UpdateGlobs(...)` + `randString(...)`

- `text[...]`
  - 规则：生成特定架构机器码
  - 实现：`generateText(...)`（`ifuzz.Generate`）

- `buffer` / `array[int8]` 等 blob
  - 规则：随机长度随机字节，或按范围
  - 实现：`BufferType.generate` 的 `BufferBlobRand/Range`

## 4.3 资源与复合类型

- `resource`
  - 规则：优先复用已有资源；不够时尝试调用 ctor 创建；再不行回退 special value
  - 实现：`ResourceType.generate`、`existingResource`、`createResource`

- `ptr[in/out/inout, T]`
  - 规则：生成被指向对象，再分配地址；可选指针允许 null/special pointer
  - 实现：`PtrType.generate` + `allocAddr`

- `array[T]` / `array[T, N]` / `array[T, M:N]`
  - 规则：按随机/固定/范围长度递归生成元素
  - 实现：`ArrayType.generate`

- `struct`
  - 规则：按字段顺序生成；字段可有方向、条件、overlay
  - 实现：`StructType.generate` + `generateArgs`

- `union`
  - 规则：随机选一个分支；条件 union 先放默认，后续再补
  - 实现：`UnionType.generate`

- `len/bytesize/bitsize/offsetof`
  - 规则：生成时先占位，后续根据引用对象回填
  - 实现：`LenType.generate`（先 0）+ size assign 阶段回填

---

## 5. 语法层规则（写描述时最常用）

官方语法总览见：
- `docs/syscall_descriptions_syntax.md`

特别建议重点看：
- Ints（范围、对齐、位域、大小端）
- Structs/Unions（`packed`、`varlen`、条件字段）
- Resources（继承、生产者/消费者约束）
- Length（`len[parent]`、路径表达式）
- Call attributes（`no_generate`、`no_minimize`、`timeout` 等）

---

## 6. corpus 文本里你会看到什么

序列化位于：`prog/encoding.go`

常见表现：
- 常量：`0x1234`
- 指针：`&AUTO=...`
- 资源：`<r0=>` / `r0`
- union：`@option=...`
- data/string：`"..."` 或十六进制串

这就是为什么你在 unpack 后看到的大量 `openat$xxx(...)`、`r0`、`&AUTO` 能直接映射回上述类型系统。

---

## 7. 对你当前问题的直接结论

1. `string[filesystem]`：
   - 值来自 `filesystem = ...` 列表，运行时随机选一个。
2. `filename`：
   - 运行时由 `filenameImpl()` 生成（常见 `./fileN`），并结合历史 `s.files` 复用。
3. “正则”相关：
   - syzlang 主要是 `glob[...]` 路径模式，不是 regex 类型。
   - 复杂约束依赖条件表达式（整数逻辑），不是字符串正则。
