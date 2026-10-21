# CEP：EDR 如何实时匹配多事件攻击序列（原理）

## 一句话
**事件关联**先根据身份和关系确定“哪些操作属于哪个进程”；**CEP（复杂事件处理）**再对不断到来的事件流应用顺序、时间窗口和条件规则，识别满足某种行为模式的事件序列。CEP 是规则执行技术，不会自行理解攻击意图。

## 原理
假设采集到的事件已归一化，且同一进程实例具有稳定的 `ProcessGuid`：

| 时间 | 事件 | ProcessGuid |
|---|---|---|
| 10:00:01 | Word 创建 PowerShell | A |
| 10:00:02 | PowerShell 连接外部 IP | A |
| 10:00:03 | Chrome 网络连接 | B |
| 10:00:04 | PowerShell 创建 EXE | A |

**关联与检测是两步**：
```text
原始事件 → HostID/ProcessGuid 关联 → 按时间组织同一进程事件
                                   ↓
                 CEP 匹配 A→B→C（限时 10 秒）
                                   ↓
                              告警/调查
```
- **A（进程创建）**：`ParentImage=winword.exe` 且 `Image=powershell.exe`。
- **B（网络连接）**：与 A 相同的进程实例发起网络连接。
- **C（文件创建）**：该进程创建可执行文件，且发生在 B 后。
- **时间窗口**：例如从 A 到 C 不超过 10 秒（仅教学示例，并非通用 EDR 阈值）。

### 声明式匹配：MATCH_RECOGNIZE
支持该语法的流式 SQL 引擎可表达类似逻辑。下述代码展示模式的**核心部分**，并非保证可直接运行的完整 SQL：

```sql
MATCH_RECOGNIZE (
  PARTITION BY DeviceId, ProcessGuid
  ORDER BY EventTime
  PATTERN (A B C)
  DEFINE
    A AS A.EventType = 'ProcessCreated'
          AND A.ParentImage = 'winword.exe'
          AND A.Image = 'powershell.exe',
    B AS B.EventType = 'NetworkConnection',
    C AS C.EventType = 'FileCreated'
          AND C.TargetFilename LIKE '%.exe'
)
```
- `PARTITION BY`：按设备和进程实例划分，避免把无关进程拼接成一条攻击链。
- `ORDER BY`：事件时间顺序；生产中还需处理迟到和乱序事件。
- `PATTERN (A B C)`：定义有序匹配；**并不天然允许 A、B、C 之间任意插入事件**，跳过无关事件的语义需由引擎的模式定义显式处理。
- `DEFINE`：定义各事件条件；还需按引擎语法加入 10 秒窗口、匹配跳过策略等，常见流处理实现见 Apache Flink CEP。

### 底层：按 Key 维护状态机
可以把简单规则近似看成：
```text
S0 --收到A--> S1 --收到B--> S2 --收到C且未超时--> 匹配
```
CEP 引擎在每个关联键（如 DeviceId + ProcessGuid）上保存并发部分匹配与计时状态，维护状态转移、窗口过期和清理。复杂模式常使用 NFA（非确定有限自动机）或等价的模式匹配机制；并不是消除了 if-else，而是**抽象和工程化了大量条件判断及状态管理**。

| 问题 | 手写 if-else | CEP |
|---|---|---|
| 单条事件判断 | 直接判断 | 可处理，但不必引入 CEP |
| A→B→C 顺序与时间窗 | 自行保存状态/定时 | 声明式模式与窗口 |
| 大量进程并行匹配 | 自行维护按键状态表 | 分区状态与并行计算 |
| 乱序、迟到、重复事件 | 自行设计容错 | 取决于具体引擎的事件时间、水位线等机制 |

## 审计
- 首先验证身份：使用 **HostID + ProcessGuid**，或 `HostID + PID + 创建时间`，不要只按 PID 关联（PID 会复用）。
- 区分**证据边**（同一 ProcessGuid、明确父子关系）与**推断边**（时间邻近、五元组或跨主机推断）；相邻不等于因果。
- 明确事件时间还是到达时间、乱序策略、匹配窗口、是否跳过无关事件，以及进程退出后的状态回收。
- 用无害的 Office/PowerShell 管理操作和不同进程间交错事件测试误报，不能把匹配命中直接当成攻击证实。

## 易错
- **事件关联 ≠ 检测**：JOIN/Hash Map/进程树负责事件归属；CEP 负责查找行为序列；威胁判断由专家规则、评分或模型承担。
- **CEP ≠ 机器学习**：规则由人定义，CEP 负责高效执行。
- **PATTERN (A B C) ≠ 任意三个事件凑齐**：还受分区、顺序、匹配策略和时间窗限制。
- **同一个 PID ≠ 同一个进程实例**；同一设备上的不同进程也不能只按时间拼接。

关联：[EDR 技术发展史](README.md) · [EDR 行为观测与检测决策](edr-observation-vs-detection.md)

参考：[Apache Flink CEP](https://nightlies.apache.org/flink/flink-docs-stable/docs/libs/cep/) · [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
