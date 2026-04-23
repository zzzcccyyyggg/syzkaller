
# 三、Overview

## 1、整体架构

% ---- 设计出发点：与现有方案的本质区别 ----

现有的内核并发 fuzzing 方案——无论是基于调度探索的（如 Conzzer~\cite{conzzer}、SegFuzz~\cite{segfuzz}），还是基于候选筛选的（如 Razzer~\cite{razzer}）——都将"发现潜在竞争"与"确认竞争成立"耦合在同一执行循环中。具体而言，它们在每次执行时既需要达到候选访问位置，又需要在同一次执行中通过调度使访问真正重叠。这种耦合带来了根本性的吞吐量瓶颈：Conzzer 需要为每次执行设置断点和线程暂停/恢复以控制交错；SegFuzz 需要在每次 fuzzing 执行中注入延迟以探索不同的 interleaving segment。这些调度操作直接拖慢了主 fuzzing 循环，使系统在单位时间内能执行的测试数量大幅减少。

我们的系统采用截然不同的设计：**fuzzing 主循环（占 90\% 执行预算）不执行任何主动调度**。程序组在同步起跑后自然并发执行，内核检测模块被动记录访问信息，执行后仅通过时间阈值过滤来识别 May-Race Pair。主循环中没有断点、没有线程暂停、没有延迟注入——其吞吐量不承受调度干预开销。剩余 10\% 预算用于专用的时序探索队列（§IV.2），仅对已确认存在共享访问的程序组进行轻量延迟变异——这是两阶段之间的信息桥梁，而非主循环的一部分。需要明确的是，被动检测并非零成本：编译期插桩引入指令膨胀、执行后 ftrace buffer 的读取（最长约 2 秒的稳定读取等待）和 $O(n^2)$ 配对分析构成每次执行的固定检测开销。关键区别在于，这些成本是**执行后的被动分析**——它们不改变程序的执行路径和时序，不破坏并发行为的自然性，且可与下一次执行部分重叠。相比之下，Conzzer 和 SegFuzz 的断点设置与延迟注入发生在执行期间，直接改变运行时行为并延长关键路径。所有主动调度开销被推迟到独立的 validation 阶段，且此时调度有明确目标（已知 $\Delta t$ 和上下文），而非盲目搜索。我们在评估章节（§VII）量化了插桩开销和检测延迟对实际吞吐量的影响。

% ---- 并发测试用例的定义 ----

在本系统中，一次并发测试的输入为一个**程序组**（Program Group），由两个 syzkaller 程序组成：主程序（primary）为当前 fuzzing 循环中被选中或变异产生的程序；伙伴程序（partner）从现有 corpus 中随机选取后经资源对齐得到。两个程序各自包含一系列系统调用序列。程序组的执行模型确保二者在同一内核实例中并发运行，从而创造跨线程竞争的机会。

% ---- 并发执行模型 ----

程序组的执行基于**同步起跑 barrier**机制。每个程序被分配给一个独立的 executor 进程（proc slot），当所有成员到达 barrier 集合点后，系统通过两阶段握手协议（聚集-释放）同时释放所有成员开始执行。执行过程中，内核侧的检测模块被动记录所有共享内存访问：变量名标识（VarName）、调用栈哈希（CallStack）、访问地址、纳秒时间戳、访问类型和线程 ID。程序组执行结束后，用户态检测器读取 ftrace buffer 并进行 $O(n^2)$ 配对分析（$n$ 为单次执行的记录数，上限 65536），筛选出满足 May-Race Pair 条件的候选对。需注意：配对分析的计算量非平凡（典型执行约数千条记录，最坏情况约 $2 \times 10^9$ 次比较），但其关键特性是**事后分析**——它在执行完成后运行，不干预执行中的时序和路径。当前实现中，配对分析与 trace 读取占用同一 executor 的 proc slot 直至完成，下一次 barrier 派发需等待其结束；我们在 §VII 报告该开销对端到端吞吐量的实际影响。

% ---- 两阶段数据流 ----

系统的工作流以 May-Race Pair 为衔接分为两个阶段。**Fuzzing 阶段**以高吞吐量生成和执行并发程序组，在自然并发执行中持续产出 May-Race Pair。每个 pair 连同发现时的程序组、barrier 配置和执行历史一并持久化到 corpus 数据库。**Validation 阶段**作为独立进程运行，增量消费数据库中的候选：它对每个候选施加定向调度（延迟注入），使双方访问在时间上真正重叠，从而确认真实竞争。两阶段通过数据库松耦合——fuzzing 只写入，validation 只读取——使发现阶段的吞吐量完全不受调度开销影响。


## 2、May-Race Pair 定义与设计理由

% ---- 形式化定义 ----

\begin{definition}[May-Race Pair]
给定两次内存访问 $a_1 = (tid_1, addr_1, size_1, type_1, t_1)$ 和 $a_2 = (tid_2, addr_2, size_2, type_2, t_2)$，其中 $tid$ 为线程标识，$addr$ 和 $size$ 为访问地址与大小，$type \in \{R, W, F\}$，$t$ 为纳秒时间戳。若以下条件全部成立，则称 $(a_1, a_2)$ 为一个 May-Race Pair：
\begin{enumerate}
    \item $tid_1 \neq tid_2$（不同线程）
    \item $[addr_1, addr_1 + size_1) \cap [addr_2, addr_2 + size_2) \neq \emptyset$（地址重叠）
    \item $type_1 = W \lor type_2 = W$（至少一方为写）
    \item $|t_1 - t_2| \leq \tau$（时间差不超过阈值）
    \item $\nexists\ a_f = (*, addr_f, size_f, F, t_f)$ 使得 $\min(t_1,t_2) < t_f < \max(t_1,t_2)$ 且 $[addr_f, addr_f+size_f) \cap [addr_1, addr_1+size_1) \neq \emptyset$（中间无释放）
    \item $\text{Locks}(a_1) \cap \text{Locks}(a_2) = \emptyset$（不持有相同锁）
\end{enumerate}
\end{definition}

条件 (1)--(3) 对应数据竞争的前三个必要条件，在运行时可直接观测。条件 (4) 是对"并发执行"这一最难验证条件的松弛：真实数据竞争要求两次访问在时间上完全重叠（$\Delta t = 0$），而 May-Race Pair 仅要求 $\Delta t \leq \tau$。条件 (5) 和 (6) 是过滤条件，分别排除已被释放的无效配对和已受锁保护的安全配对。

% ---- 为什么它是正确的中间抽象 ----

May-Race Pair 的设计理由在于其三重属性：**运行时确认性**——每个 pair 都源自真实执行，条件 (1)--(3)(5)(6) 均已被运行时动态验证，而非静态推断；**可量化距离**——$\Delta t$ 直接度量该 pair 距真实竞争的"距离"，为后续调度提供精确的延迟指引（只需"推动" $\Delta t$ 到 0）；**自然产出性**——它可在不施加任何主动调度的自然并发执行中被发现，无需断点、线程暂停或延迟注入等运行时干预。

这与 SegFuzz 的 interleaving segment 和 Conzzer 的 concurrent call pair 形成对比。Interleaving segment 描述的是线程间指令序列的偏序关系，其覆盖度增长要求对同一访问点组合尝试不同的交错方式——这需要主动调度才能推进。Concurrent call pair 标记了哪些系统调用"可能"并发执行，但不提供运行时时间距离信息——后续验证仍需在整个调度空间中搜索。May-Race Pair 则同时提供了"哪两个指令可能竞争"的精确定位和"如何让它们真正竞争"的定量信息（$\Delta t$ → 所需延迟），使 validation 阶段的搜索从盲目探索收敛到有目标的参数扫描。

% ---- 与 DataCollider 的关系 ----

May-Race Pair 与 DataCollider~\cite{datacollider} 的采样-延迟机制在结构上有相似处：两者都观察共享访问的时间接近性。然而两者在方法论层面有本质分歧，且 MRP 的核心贡献不在于"被动版 DataCollider"，而在于其作为**覆盖引导 fuzzing 的一级抽象**所提供的独特能力。

DataCollider 是独立的检测器（standalone checker）：在运行时随机采样一次共享访问，立即插入短延迟等待另一线程命中同一地址。其采样-确认是原子操作，发现率仅随执行时间线性增长，且无法利用 fuzzing 的变异-选择循环扩大探索范围。MRP 则是嵌入在覆盖引导 fuzzing 循环中的信息抽象：它不仅标记"哪些访问可能竞争"，还提供可量化的调度距离（$\Delta t$），且新 VarName 对的发现直接指导变异方向（触发时序探索入队、影响伙伴选择）。这种**覆盖反馈**——MRP 作为并发覆盖度信号驱动 fuzzing 的探索策略——在 DataCollider 中完全不存在，因后者不做输入变异。

此外，DataCollider 的检测覆盖与采样命中率耦合（低频路径难以覆盖），而我们的全量被动记录覆盖所有被执行的共享访问。Validation 阶段则以 $\Delta t$ 为精确指引做定向延迟扫描，而非 DataCollider 固定时长的盲等窗口，使得验证效率从随机概率提升为有目标的参数搜索。

% ---- 阈值策略 ----

阈值 $\tau$ 控制候选的精度-召回权衡。我们采用两级阈值策略：正常发现使用 $\tau_{\text{normal}} = 10\text{ms}$，时序探索阶段放宽至 $\tau_{\text{wide}} = 500\text{ms}$。$\tau_{\text{normal}} = 10\text{ms}$ 的选取基于以下考量。Linux CFS 调度器中，`sysctl_sched_latency` 默认 6ms、`sched_min_granularity_ns` 默认 0.75ms，两个 runnable 线程各获约 3ms 时间片。两个线程的系统调用若在同一或相邻调度窗口执行，其内核访问时间差通常落入 0--10ms 范围（约 1.5--3 个时间片）。低于此阈值的 pair 代表"在自然调度下几乎同时执行"的访问——它们是通过微秒级调度调整最可能被推至完全重叠的候选。过窄的阈值（如 $100\mu\text{s}$）会遗漏大量因调度抖动错开但实质具备竞争能力的配对；过宽的阈值（如 $100\text{ms}$）则引入大量因果无关的配对，显著降低后续验证命中率。我们在评估章节（§VII）提供 $\tau$ 在 $[100\mu\text{s},\ 100\text{ms}]$ 范围内的灵敏度分析。时序探索阶段放宽至 $\tau_{\text{wide}} = 500\text{ms}$，在已确认存在共享访问的程序组中捕获更多潜在 pair——这些 pair 虽然当前 $\Delta t$ 较大，但通过后续延迟注入有可能缩短。

% ---- 基于四元组的并发覆盖度 ----

为指导 fuzzing 阶段的探索方向，我们以四元组 $(\textit{VarName}_1,\textit{VarName}_2,\textit{CallStack}_1,\textit{CallStack}_2)$ 定义**并发覆盖度**。其中 $\textit{VarName} = \text{BKDRHash}(\textit{funcName} : \textit{block\_id} \ll 16\ |\ \textit{instr\_id})$ 是共享访问在源码中的静态位置标识（编译期常量），$\textit{CallStack}$ 是访问发生时内核调用栈帧的运行时哈希。新的四元组被视为新覆盖——同一对变量在不同执行路径下被访问会产生不同的覆盖。去重采用三层结构：
\begin{itemize}
    \item \textbf{层 1}（VarName 对）：$(\textit{VarName}_1, \textit{VarName}_2)$ 标识一个变量对，是最粗粒度的新颖性判据。新 VarName 对的发现触发时序探索入队。
    \item \textbf{层 2}（Stack 组合）：每个 VarName 对下最多保留 100 个不同的 $(\textit{CallStack}_1, \textit{CallStack}_2)$ 组合，防止组合爆炸。
    \item \textbf{层 3}（完整四元组）：精确去重，同一四元组只记录一次。
\end{itemize}


## 3、两阶段各自的目标

% ---- Fuzzing 阶段目标 ----

Fuzzing 阶段的目标是**最大化 May-Race Pair 的 VarName 对覆盖广度**。它不尝试确认任何 pair 是否为真实竞争，而是专注于：(a) 通过资源对齐的程序组使更多内核共享数据结构被并发访问，从而发现新的共享变量对；(b) 通过时序探索使已知变量对附近发现更多 CallStack 组合，积累更丰富的验证候选。该阶段的吞吐量指标是单位时间内的新 VarName 对发现数，而非竞争确认数。

% ---- Validation 阶段目标 ----

Validation 阶段的目标是**以最高命中率将 May-Race Pair 转化为确认的真实竞争**。它接收 fuzzing 阶段持久化的候选（包含程序组、$\Delta t$、replay history），通过定向延迟调度使双方访问在时间上真正重叠。成功的标准是触发内核 data-race 检测器（如 KCSAN）的报告。该阶段的效率指标是验证命中率（confirmed races / attempted pairs）和单位时间确认数。

% ---- 信息流的关键特征 ----

两阶段之间的信息流是单向且自包含的：每个 May-Race Pair 自身携带了 validation 所需的全部上下文——输入（程序组）、目标（四元组标识的访问位置）、调度提示（$\Delta t$ → 延迟估计）和前提条件（replay history → 状态还原）。这意味着 validation 阶段可以在 fuzzing 结束后任意时刻运行，也可以与 fuzzing 同时运行并增量消费新产出的 pair。两阶段无需同步、无需共享内存状态、无需在线通信——数据库是唯一接口。需要说明的是，fuzzing 阶段内部存在局部反馈回路：检测产出的 MRP 及其 $\Delta t$ 会影响时序探索的延迟参数选择和程序组的入队决策（§IV.2）。但此反馈不跨越到 validation 阶段——validation 消费的是持久化后的完成品，无需与 fuzzing 的运行时状态交互。


---

# 四、Fuzzing Phase

## 1、资源感知的并发程序组生成

% ---- 问题与对比 ----

让两个程序并发执行并不必然产生有意义的共享访问。内核对象是命名空间化的：两个程序各自调用 `open("/mnt/kccwf/testfile0")` 和 `open("/mnt/kccwf/testfile1")` 时，它们在逻辑上都操作文件系统，但在运行时触及的是不同的 inode 内存对象——不存在共享地址。Conzzer~\cite{conzzer} 通过识别"并发调用对"来选择可能交互的系统调用，但其判断基于系统调用名称的语义类别，不保证运行时操作同一内核对象实例。SegFuzz~\cite{segfuzz} 使用单进程的多线程执行模型，天然共享地址空间，但其 interleaving coverage 的增长不依赖于对象同一性的保证。

本系统面临更明确的约束：程序组中的两个程序作为独立进程执行（barrier mode），不共享用户态地址空间，其对内核对象的访问完全取决于系统调用参数。因此，程序组生成的核心挑战是在**参数层面**确保两侧操作同一个内核对象实例。

% ---- 两层资源对齐（Object Linking V2） ----

我们设计了两层资源对齐机制，在构造程序组时统一双方的对象标识符：

**第一层：同名系统调用对齐**。若 primary 和 partner 中包含名称完全相同的系统调用（如两侧都有 `open$kccwf`），则直接将 partner 中该调用的对象标识符参数复制为与 primary 一致。例如，若 primary 的 `open$kccwf` 使用路径 `/mnt/kccwf/testfile0`，则 partner 中同名调用的路径也被覆写为 `/mnt/kccwf/testfile0`。

**第二层：跨变体族对齐**。对于名称不同但操作同类对象的系统调用，系统维护一张**对象族表**（Object Family Table），将共享同类内核对象的系统调用分组。例如，`open$kccwf`、`stat$kccwf`、`chmod$kccwf`、`unlink$kccwf`、`rename$kccwf` 同属 kccwf 文件路径族，`bind$bt_sco`、`connect$bt_sco`、`sendmsg$bt_sco` 同属蓝牙 SCO 地址族。对齐时通过查表确定每个系统调用的对象标识符位于哪个参数索引（如 `open` 的 arg[0]、`openat` 的 arg[1]、`bind` 的 arg[1]），然后将 primary 中该族的实际参数值复制到 partner 对应位置。

**安全约束与改写限制**：
\begin{itemize}
    \item 路径中含 `/proc/self/`、`/sys/kernel/debug/` 等执行上下文相关标识符的访问不参与对齐（这些不代表独立持久对象）。
    \item 依赖 `dirfd` 的 `*at` 系列系统调用（如 `openat`、`faccessat`）需要验证其 dirfd 是否也被正确对齐，否则标记为不安全跳过。
    \item 每个对象族的改写数量上限为 3 次，防止过度改写破坏程序的内部状态依赖。
    \item 基于 fd 返回值的链式依赖（如 `r0 = open(...)` → `read(r0, ...)`) 不需要改写——fd 通过调用链天然继承对象身份。
\end{itemize}

% ---- 效果说明 ----

经过资源对齐，程序组的两个程序虽然来自不同的 corpus entry、经过独立变异，但在执行时将操作同一文件 inode、同一蓝牙连接、同一设备结构——这大幅提高了跨线程共享内存访问的概率，从而为 May-Race Pair 的产出奠定基础。当前系统定义了 7 个对象族,覆盖文件系统（绝对路径族 27 个 syscall variant + 相对路径族 15 个 `*at` variant + 目录族）、蓝牙协议（SCO/L2CAP/RFCOMM 各一族）、UNIX socket 和块设备。


## 2、基于 Pair 的时序探索

% ---- 动机与对比 ----

资源对齐解决了"能否访问同一地址"的前提问题，但两侧的具体访问时刻仍取决于各自的执行速度和内核调度。在自然并发执行中，即使双方触及同一变量，也可能因微秒级时序偏差超出阈值 $\tau$ 而未被捕获为 May-Race Pair。此现象在 fuzzing 阶段尤为突出：大量潜在竞争对"存在"但因时序稍有错开而"不可见"。

SegFuzz 通过在每次 fuzzing 执行中注入延迟来探索不同的 interleaving segment 覆盖——这意味着其主循环的每次执行都承担调度开销。我们的设计不同：**主循环（Pair Discovery Queue）不注入任何延迟**，以保持最大吞吐量；延迟注入仅在一个专用的辅助队列（Timing Exploration Queue）中执行，且只对已确认存在共享访问的程序组进行。这将调度的搜索成本隔离在 10\% 的执行预算内，而非分摊到每次执行。

% ---- 双队列架构 ----

系统维护两个并行执行队列：

**Pair Discovery Queue（发现队列，90\% 预算）**：以正常阈值 $\tau_{\text{normal}} = 10\text{ms}$ 执行资源对齐后的程序组，不注入任何延迟。其唯一目标是发现新的 $(\textit{VarName}_1, \textit{VarName}_2)$ 对。当一次执行产出的 pair 包含对 VarName Pair Registry 而言全新的变量对时,该程序组被标记为"高价值"并自动入队 Timing Exploration Queue。

**Timing Exploration Queue（时序探索队列，10\% 预算）**：以放宽阈值 $\tau_{\text{wide}} = 500\text{ms}$ 重新执行高价值程序组，并施加延迟变异。其目标有二：(a) 在同一变量对上发现更多 CallStack 组合（扩充四元组覆盖）；(b) 使原本超出 $\tau_{\text{normal}}$ 的 pair 缩小 $\Delta t$（提高验证成功率）。

% ---- 延迟注入策略 ----

时序探索通过在程序中插入 `syz_delay(microseconds)` 伪系统调用来调整执行时序。延迟被插入到系统调用序列的特定位置，使目标调用的执行时刻被推迟。系统实现了基于已知 $\Delta t$ 的**信息引导策略**（timediff）作为默认策略：

给定一个已发现的 pair，设其两侧访问的时间差为 $\Delta t$，第一方（时间较早）位于程序 $P_i$ 的第 $k$ 个系统调用，第二方（时间较晚）位于程序 $P_j$ 的第 $l$ 个系统调用。timediff 策略的核心逻辑为：
\begin{enumerate}
    \item 在程序 $P_i$ 的第 $k$ 个调用之前插入延迟 $d = \Delta t \times U(0.5, 1.5)$，其中 $U$ 为均匀分布随机抖动。这使第一方减速，为第二方创造追赶窗口。
    \item 以 30\% 概率额外在第 $k$ 个调用之后插入微调延迟（$d' \sim U(d/4, d/2)$），探索边界 timing。
    \item 若 $\Delta t$ 极小（$< 100\mu\text{s}$），转为在随机一侧插入小延迟做边界扰动。
\end{enumerate}

此外系统提供定向策略（在竞争 syscall 附近随机插入延迟，用于 $\Delta t$ 信息不可靠时的探索）、二分搜索策略（在已有最佳方案上 $\pm 50\%$ 微调）和随机策略（完全随机，作为基线）。

% ---- 迭代与终止 ----

每个 (VarName, CallStack) 对最多尝试 $N_{\max} = 20$ 次时序探索。每次生成一组延迟方案后执行 5 次（应对非确定性），若触发率 $\geq 10\%$（至少 1 次产出目标 pair）则视为成功。每程序中最多插入 5 个延迟调用，延迟范围 $[10\mu\text{s},\ 200\text{ms}]$。当某 VarName 对已积累足够数量的 corpus entry 时（由 `MaxCorpusCountPerVarName` 控制），停止对该对的继续探索，将资源让给新发现的变量对。

% ---- 信息价值 ----

时序探索的核心贡献不仅是增加 pair 数量，更重要的是**缩小已有 pair 的 $\Delta t$**。一个初始发现时 $\Delta t = 8\text{ms}$ 的 pair，经过 timediff 策略可能被缩短至 $\Delta t = 200\mu\text{s}$——这直接降低了 validation 阶段的调度难度。换言之，Timing Exploration 是在为 Validation 阶段做"预热"：它不确认竞争，但让候选离确认更近一步。


---

# 五、Validation Phase

## 1、整体流程与核心挑战

% ---- 目标与输入 ----

Validation 阶段接收 fuzzing 阶段产出的 May-Race Pair 候选集。每个候选是一个自包含记录：
$$\text{Entry} = (\text{Programs}, \text{Barrier}, \text{Pairs}, \Delta t, \text{ReplayHistory}, \text{Profile})$$
其中 Programs 是发现该 pair 时的程序组，Barrier 是 barrier 配置快照，$\Delta t$ 是发现时的最小时间差，ReplayHistory 是发现前的执行历史，Profile 是四元组标识。目标是使候选对双方访问真正重叠——即将 $\Delta t$ 从当前值精确推到 0。

% ---- 基本验证思路 ----

基本做法是：(1) 还原发现 pair 时的系统状态（通过 replay history）；(2) 重新执行产出该 pair 的程序组；(3) 在 barrier 启动时注入延迟，使程序组中的一侧整体后移，创造两侧访问重叠的窗口。若确认产生真实并发访问重叠（KCSAN报告 或检测器确认），则该 pair 被标记为真实竞争。

然而，实际验证面临三个核心挑战：

**挑战 1：执行路径不确定性**。同一程序在不同执行中可能走过不同的内核路径。即使系统调用序列相同，内核内部的条件分支（如缓存命中/Miss、锁竞争结果、内存分配器状态）会导致目标访问点不总是被触及。需要通过多次重复和参数扫描来覆盖这种不确定性。

**挑战 2：状态前提依赖**。许多竞争依赖先前操作建立的系统状态。例如，文件系统竞争通常要求目标文件已存在（需要先前的 `create`/`open` 操作），蓝牙竞争要求连接已建立（需要先前的 `bind`/`connect`）。直接执行目标程序组而不还原前提状态，竞争双方可能无法到达目标代码路径。

**挑战 3：候选数量远超验证预算**。Fuzzing 阶段在数小时内可积累数万个候选。每个候选的验证需要 VM 启动、状态还原、多次重复执行，成本远高于一次 fuzzing 执行。必须智能分配验证资源：优先尝试更可能成功的候选，对反复失败的候选降低投入。


## 2、定向延时调度策略

% ---- 解决挑战 1 ----

针对执行路径不确定性，我们采用**指数延迟扫描**（Exponential Delay Sweep）策略。核心观察是：给定候选 pair 的 $\Delta t$，理想的启动延迟应使两侧访问恰好重叠——但由于每次执行的实际到达时间有抖动，最优延迟值在一个范围内浮动。因此，不应只尝试单一延迟点，而应系统性地在一个范围内扫描。

延迟序列采用指数分布，使小延迟区间获得更密集的采样：
$$d_i = \tau_{\max} \times \left(\frac{i}{n-1}\right)^{p}, \quad i = 0, 1, \ldots, n-1$$
其中 $n = 10$ 为扫描步数，$\tau_{\max} = 800\mu\text{s}$ 为最大延迟，$p = 2.0$ 为曲线指数。这产生的延迟序列为 $\{0, 9, 36, 79, 139, 218, 314, 428, 559, 800\}\mu\text{s}$——前 5 步覆盖 $0$--$139\mu\text{s}$（密）、后 5 步覆盖 $139$--$800\mu\text{s}$（疏）。设计理由是：多数高质量 MRP 的 $\Delta t$ 本身较小（在正常阈值 $10\text{ms}$ 下发现），其最优调度延迟也在微秒级；指数分布将更多采样点集中在此区间。

需要说明 $\tau_{\max} = 800\mu\text{s}$ 与发现阈值 $\tau = 10\text{ms}$ 之间的数量级差异。扫描范围不需要覆盖原始 $\Delta t$ 的全部跨度，原因有二。其一，进入 validation 的候选通常已经过 fuzzing 阶段的时序探索预压缩（§IV.2）：初始 $\Delta t = 8\text{ms}$ 的 pair 在 timediff 策略下被缩小至数百微秒级后才被持久化为高优先级候选。其二，barrier 启动延迟是对整个程序的全局时移——它不等于目标访问点的 $\Delta t$ 变化量，因为延迟传播受中间系统调用耗时和内核调度的非线性影响。$800\mu\text{s}$ 的扫描范围在实践中覆盖了绝大多数经预压缩候选的有效调度窗口。对于未经时序探索的大 $\Delta t$ 候选（$> 1\text{ms}$），系统以较低优先级处理——这是精度优先于召回的有意取舍，在限制章节进一步讨论。

延迟以**barrier 启动延迟**的形式注入：
$$\text{StartDelays}[\text{proc}] = \begin{cases} d_i & \text{if proc} = 0 \text{ (first member)} \\ 0 & \text{otherwise} \end{cases}$$
即程序组的第一个成员被延迟 $d_i$ 后开始执行，其余成员正常启动。这等效于将第一侧的所有系统调用整体后移 $d_i$。

每一步扫描执行 $R = 10$ 次重复（VerifyRepeatTimes），以覆盖单次执行的非确定性。整个验证请求序列（replay + verify）打包在单一 RPC 批量会话中执行：
$$[\underbrace{\text{replay}_0, \ldots, \text{replay}_k}_{\text{state restoration}},\ \underbrace{\text{verify}_{d_0}^{(1)}, \ldots, \text{verify}_{d_0}^{(R)}, \ldots, \text{verify}_{d_{n-1}}^{(R)}}_{\text{delay sweep}}]$$
这避免了每步重新建立 SSH 连接和 VM 通信的开销。


## 3、状态还原

% ---- 解决挑战 2 ----

为解决状态前提依赖问题，我们引入**Replay History 回放**机制。其直觉是：若某 pair 在第 $k$ 次 barrier 执行中被发现，那么前 $k-1$ 次执行必然已建立了该 pair 依赖的系统状态。因此，在验证前按顺序重放这些历史执行，即可重建必要的前提条件。

**记录阶段**（Fuzzing Phase）。每个 VM 维护一个大小有限的环形缓冲区（per-VM ring buffer），记录每次 barrier 执行的完整信息：程序组序列化、barrier 配置（GroupSize、Participants）、执行覆盖率。当一个 May-Race Pair 被发现时，系统根据其新颖度决定保留的历史长度：
\begin{itemize}
    \item 全新 VarName 对（最高价值）：保留最近 1000 条历史
    \item 已有 VarName 对的新 CallStack：保留最近 100 条
    \item 完全已知的四元组：保留 1 条（仅用于最基本的状态还原）
\end{itemize}
这种分层策略确保高价值候选获得充分的状态背景，同时控制低新颖度候选的存储开销。

**回放阶段**（Validation Phase）。验证某个 entry 前，其 ReplayHistory 中的每条记录被顺序执行：
$$\text{ExecuteSequence}:\ \text{replay}_0 \to \text{replay}_1 \to \cdots \to \text{replay}_k \to \text{verify}$$
每条 replay 构造为完整的 barrier 执行请求——包含程序组和 barrier 配置——但禁用 DDRD 采集（不收集竞争信息），仅执行其系统调用以积累副作用。当 verify 请求执行时，内核中的文件系统对象已创建、socket 连接已建立、设备状态已初始化。

**History Minimization**（验证成功后）。若某 entry 验证成功（确认为真实竞争），系统随即执行历史最小化：通过逐步移除 replay 条目并重新验证，找到使竞争仍可触发的最小历史子集。三种策略可选：
\begin{itemize}
    \item **二分法**（默认）：递归二等分，每次移除一半、测试另一半是否仍可触发。$O(\log n)$ 复杂度，快速缩减。
    \item **贪婪法**：逐一移除条目，每次测试 $N_{\text{attempt}}=3$ 次确认是否仍触发。$O(n^2)$ 最坏复杂度，产出最小子集。
    \item **混合法**：先二分快速缩减，再贪婪精炼残留。
\end{itemize}
最小化后的历史成为该竞争的精简重现条件，可直接用于后续的稳定重触发和开发者复现。

**VM 快照加速**。即便有 replay 机制，VM 的启动和初始化（加载内核、设置网络、传输 executor 二进制）仍是固定开销。系统支持 QEMU snapshot 模式：首次创建 VM 后，在 executor 就绪点执行 `savevm`，后续每次验证通过 `loadvm` 跳过完整启动流程。Snapshot 还缓存 executor 二进制的路径信息，省去 SCP 传输步骤。


## 4、自适应权重调整

% ---- 解决挑战 3 ----

面对数万候选和有限时间预算，验证资源的分配直接决定最终确认数。我们设计了一套层次化的调度与回退机制，使系统自适应地聚焦高概率候选。

% ---- VarName Round-Robin 调度 ----

**分组与轮转调度**。所有候选按 $(\textit{VarName}_1, \textit{VarName}_2)$ 分组——忽略 CallStack，因为同一变量对的不同 stack 组合代表"同一竞争的不同触发路径"，验证任一即够。调度器在组间执行 round-robin 轮转，并按组内条目数升序排列：稀有 VarName 对（条目少）优先获得验证机会。直觉是：条目少的变量对可能更难触发，需要更早开始验证以利用完整时间预算。

组内优先级按 Replay History 长度升序排列（`PriorityLowHistory`）：历史短的条目通常对应更简单的重现路径——它们要么在执行初期就被发现（状态依赖少），要么经过最小化——验证效率更高。

% ---- 贝叶斯自适应回退 ----

**Beta 分布后验模型**。系统为每个 VarName 对维护累计统计 $(S, F)$（成功次数、失败次数），并用 Beta 分布的后验均值估计其"真实失败率"：
$$\text{BackoffScore} = \frac{\alpha}{\alpha + \beta}$$
$$\alpha = F \cdot (1 - \epsilon) + \alpha_0, \quad \beta = S \cdot w + \beta_0$$
其中 $\epsilon = 0.15$ 是噪声容忍率（假设 15\% 的失败源自 replay 不可靠或时序偶然偏差，而非真实不可竞争），$w = 2.0$ 是成功权重（每次成功计为双倍反证据，因为成功更可信），$(\alpha_0, \beta_0) = (0.5, 0.5)$ 为 Jeffrey's 无信息先验。

**跳过概率**：
$$P_{\text{skip}} = \min\left(\text{BackoffScore} \times (1 - \rho),\ P_{\max}\right)$$
其中 $\rho = 0.05$ 为探索保留率（保证至少 5\% 概率被验证），$P_{\max} = 0.90$ 为硬上限。首次验证（$S + F = 0$）始终执行（$P_{\text{skip}} = 0$）。

这一设计的关键特性是：(a) 不会完全放弃任何 VarName 对（最多 90\% 跳过）；(b) 单次成功即显著降低跳过概率（$w = 2$）；(c) 容忍噪声——即使某对失败 10 次，若有 1 次成功，其后验也会显著修正。

% ---- 三层跳过级联 ----

验证前对每个候选条目执行三层检查，逐层递进：
\begin{enumerate}
    \item \textbf{L1——精确匹配}：完整四元组 + 源程序已被标记为 invalid（验证失败且时间差过大）或已验证成功 → 确定性跳过。
    \item \textbf{L2——VarName 验证}：同一 $(\textit{VarName}_1, \textit{VarName}_2)$ 对的任一条目已验证成功 → 永久跳过该对所有剩余条目。理由：已确认该变量对存在真实竞争，无需重复验证。
    \item \textbf{L3——概率回退}：基于贝叶斯 BackoffScore 计算 $P_{\text{skip}}$，以此概率随机跳过。
\end{enumerate}
若某条目的所有 pair 都会被 L1/L2/L3 跳过（阈值 80\%），则跳过整个条目（避免执行昂贵的 replay 后因所有 pair 都被过滤而浪费资源）。

% ---- Backoff 后穷举 ----

当回退引导的首轮 pass 完成后（所有可调度任务耗尽或被跳过），系统进入穷举第二轮：(1) 将所有被概率跳过的条目收集并重新入队；(2) 禁用全部回退逻辑（L3 不再生效）；(3) 随机打乱顺序后穷举验证。这确保在长时间实验（如 24h 运行）中，早期因统计证据不足而被保守跳过的候选也有机会被验证，系统不会因激进回退而遗漏潜在的真实竞争。


---

# 六、Implementation

% ---- 系统基础 ----

我们基于 syzkaller 实现了上述系统。syzkaller 是目前应用最广泛的 Linux 内核模糊测试框架，其架构由 manager（管理调度）、fuzzer（变异执行）和 executor（在 VM 中执行程序）三层组成。我们的修改涉及所有三层，并额外引入了内核侧的插桩与记录模块。

% ---- 内核侧插桩 ----

**编译期插桩**。我们使用自定义 LLVM pass 在目标内核子系统的每个 Load/Store 指令前插入回调函数调用 `kccwf_rec_mem_access(addr, var_name, is_write, line, size)`。其中 `var_name` 为编译期常量，由函数名和指令 IR 序号的 BKDRHash 计算而得。该 pass 自动跳过 PGO 计数器节、常量数据段和未逃逸的栈变量，以减少不必要的插桩开销。

**运行时记录**。内核模块通过 ftrace `trace_printk` 将每次访问记录写入 `/sys/kernel/debug/tracing/trace`，包括线程 ID、变量名标识、访问地址、类型、大小、调用栈哈希和纳秒时间戳。模块支持多种工作模式（DISABLE/LOG/MONITOR/VALIDATE 等），通过 `/dev/kccwf_ctl_dev` 设备的 ioctl 控制切换。

**用户态解析**。Executor 在 barrier group 执行完毕后读取 ftrace buffer（分配 64MB 缓冲区），执行"稳定读取"（每 50ms 轮询直至连续 3 次大小不变，最长 2000ms），然后逐行解析访问记录。

% ---- Barrier 同步 ----

**两阶段握手协议**。Executor Runner 管理多个 proc slot，barrier 调度采用全有或全无（all-or-nothing）策略：只有当目标 group 的所有 proc slot 都可用时才派发。每个 proc 被派发后进入等待状态（`waiting_barrier_release_=true`），当所有成员就绪后通过 `BeginBarrierExecution()` 同时释放执行。非 barrier 请求在分配 proc slot 时跳过已被 barrier 预留的 slot（通过 `PendingBarrierMask()` 屏蔽），避免阻塞 barrier 调度。

**DDRD 集成**。Barrier 派发前调用 `PrepareForGroup()` 开启内核 LOG 模式并清空 trace buffer；所有成员完成后调用 `CollectResults()` 切换到 DISABLE 模式、解析 trace、执行竞争对分析。分析结果仅注入到 master member（index=0）的 response 中，由 manager 通过 FlatBuffers 反序列化。

% ---- 竞争对分析算法 ----

**竞争对分析算法**。用户态检测器读取所有访问记录后，执行 $O(n^2)$ 配对分析（$n$ 最大 65536 条记录）。对每对跨线程记录检查：不同 TID、至少一方写、地址区间重叠（支持不同大小的访问跨区间检测）、时间差 $\leq \tau$、中间无释放操作、不持有相同锁。满足所有条件的对生成 `may_uaf_pair_t` 结构\footnote{代码中沿用了 UAF（Use-After-Free）检测的数据结构命名（如 \texttt{may\_uaf\_pair\_t}、\texttt{FreeAccessName}/\texttt{UseAccessName}、\texttt{uaf-corpus.db}），因为系统最初从 UAF 检测的基础设施演化而来。在数据竞争语境中，这些字段分别对应竞争对的第一方和第二方访问，不暗示释放后使用语义。}，其 Signal 字段由 FNV-1a 哈希计算并保证对称性（交换双方仍产生相同 Signal），使去重不依赖配对顺序。

**系统调用归因**。每个 barrier member 在执行前通过共享内存注册其线程 ID 与 syscall 执行时间区间（SyscallHistoryRecord：tid、call\_index、prog\_idx、start\_time、end\_time）。分析阶段通过时间区间匹配将内核访问归因到具体的系统调用和程序索引。这使得后续的延迟注入能精确知道应在"哪个程序的哪个系统调用之前"插入延迟。

% ---- 对象族表 ----

Object Family 通过静态查表实现。当前定义了 7 个对象族：文件绝对路径族（27 个 syscall variant）、文件相对路径族（15 个 `*at` syscall）、目录族、蓝牙 SCO/L2CAP/RFCOMM 族各一、UNIX socket 族和软盘设备族。每个 family 记录对象标识符位于哪个参数索引。对齐时执行字节级的 `DataArg` 复制,直接将 primary 的路径/地址参数写入 partner 的对应位置。不改写基于 fd 的依赖（因为 fd 通过调用链天然继承对象身份）。

% ---- 延迟注入 ----

`syz_delay(microseconds)` 作为 syzkaller 伪系统调用实现，executor 在执行到该调用时 sleep 指定微秒。时序探索阶段按 `BeforeCall` 降序插入延迟调用（从后向前，保持索引有效性），每程序最多 5 个 delay，范围 $10\mu\text{s}$--$200\text{ms}$。

% ---- UAF Corpus 数据库 ----

May-Race Pair 通过 `uaf-corpus.db` 持久化，采用 JSON 序列化格式。每条 entry 包含程序组（可含多程序的序列化字节）、barrier 配置快照、所有发现的 pair 列表、replay plan（barrier 启动延迟）、replay history（先前执行记录列表）和时间戳。数据库支持流式加载模式（针对 >1GB 的大规模 corpus），validation 通过 `EntriesSince(timestamp)` 实现增量读取，支持与 fuzzing 同时运行。

% ---- Validation 模式 ----

Validation 作为 syz-manager 的独立运行模式（`uaf-validate`），支持三种子模式：one-shot（加载全部一次性验证）、continuous（增量检查新 entry，周期性 reload）、streaming（与 fuzz 同启，内存高效流式消费）。每个 VM 通过 QEMU snapshot 支持快速重置，验证请求以批量 RPC 执行，单次会话内顺序执行 replay 和 verify 请求序列。

% ---- 规模数据 ----

**通信协议**。Executor 与 Manager 之间通过 FlatBuffers 序列化的 RPC 通信。每次 barrier 执行完毕后，executor 将所有发现的 may-race pair（包含 VarName、CallStack、TimeDiff、TID、锁状态等 16 个字段）以 `DdrdUafPairRaw` 消息打包到执行结果中返回。Manager 反序列化后交由 fuzzer 的 pair 处理流水线进行去重、入队和持久化。

**规模数据**。系统的修改涉及约 15,000 行 Go 代码（pkg/fuzzer、pkg/racevalidate、syz-manager 包）和约 3,000 行 C/C++ 代码（executor 侧 barrier 管理、DDRD 控制器和竞争检测器）。内核插桩模块（LLVM pass + 内核 kccwf 模块）独立维护。实验在 8 个内核子系统模块上进行基准测试（xfs、btrfs、f2fs、jfs、floppy、bt-stack、ptmx、dsp），每个模块使用独立的 4 核 4GB 内存 QEMU VM 实例。


## Limitations

本系统的设计存在以下已知局限。

**检测覆盖受限于插桩范围**。内核侧 LLVM pass 仅对显式编译的子系统模块插桩。未被选入的子系统（如网络协议栈核心路径、内存管理子系统）中的竞争无法被发现。汇编代码和内联汇编中的内存访问不被 LLVM pass 覆盖。此外，KCSAN 自身基于编译器插桩和运行时采样，存在结构性假阴性：标记为 `data_race()` 的有意竞争、编译器优化消除的访问、以及采样概率未命中的并发窗口均可能导致真实竞争被漏报为验证失败。系统通过多次重复（$R=10$）部分缓解 KCSAN 的采样漏报，但无法消除其结构性盲区。关于 KCSAN 作为 ground truth 的假阳性问题：KCSAN 的报告条件（同一地址、至少一方写、无 annotation 标记）具有极高精确度，文献中 KCSAN 假阳性率极低~\cite{kcsan}。我们在 §VII 中对所有确认的竞争进行人工分类（benign/harmful），确保报告数据的可信度。

**仅支持两线程竞争**。当前 barrier 机制和配对分析限于两个并发执行体。涉及三个或更多线程的竞争模式（如 ABA 问题、多写者竞争）不在检测范围内。扩展到 $k > 2$ 的 group 在分析复杂度（$O(n^k)$ 配对）和调度空间上面临组合爆炸。

**对象族表覆盖有限**。当前 7 个对象族覆盖文件系统、蓝牙和 UNIX socket，但 TCP/UDP 网络栈、cgroup 控制组、USB 设备、内存映射（mmap）等主要子系统尚未纳入。未被覆盖的子系统中，程序组两侧可能操作不同的内核对象实例，导致共享访问率偏低。对象族表的扩展是工程性工作——需为每个新子系统识别对象标识符参数的位置和对齐语义——但不涉及方法论变更。

**验证扫描范围与大 $\Delta t$ 候选**。指数延迟扫描的最大范围为 $800\mu\text{s}$，依赖时序探索的预压缩将候选 $\Delta t$ 缩小至此范围内。对于时序探索未能有效压缩的候选（$\Delta t \gg 1\text{ms}$），当前验证策略可能不充分。这代表了精度优先于召回的设计取舍——系统优先确认高质量候选，而非对所有候选提供等概率覆盖。

**自适应调度的超参数**。Bayesian 回退中的噪声容忍率 $\epsilon = 0.15$、成功权重 $w = 2.0$、探索保留率 $\rho = 0.05$ 和最大跳过概率 $P_{\max} = 0.90$ 均为经验设定值，未经系统性超参数搜索。这些值在当前实验规模下表现合理，但其最优性未被证明，且可能不适用于候选分布显著不同的场景。

