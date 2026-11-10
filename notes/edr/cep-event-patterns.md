# CEP：EDR 如何实时匹配多事件攻击序列（原理）

## 一句话
**事件关联**先根据身份和关系确定“哪些操作属于哪个进程”；**CEP（复杂事件处理）**再对不断到来的事件流应用顺序、时间窗口和条件规则，识别满足某种行为模式的事件序列。CEP 是规则执行技术，不会自行理解攻击意图。

## 原理
假设采集到的事件已归一化，映像名称统一为basename，且同一进程实例具有稳定的 `ProcessGuid`：

| 时间 | 事件 | ProcessGuid |
|---|---|---|
| 10:00:01 | PowerShell创建记录，父映像字段为Word | P-A |
| 10:00:02 | PowerShell网络连接记录 | P-A |
| 10:00:03 | Chrome网络连接记录 | P-B |
| 10:00:04 | PowerShell创建后缀为.exe的文件 | P-A |

这里P-A/P-B是进程实例，下面的A/B/C则是模式阶段，不是同一类标识。父映像字段只证明记录父关系；网络事件代表请求还是成功，取决于事件源语义。

**关联与检测是两步**：
```text
原始事件 → HostID/ProcessGuid关联 → 按时间组织同一进程事件
                                   ↓
                 CEP匹配A→B→C（限时10秒）
                                   ↓
                              告警/调查
```
- **A（进程记录）**：`ParentImage=winword.exe` 且 `Image=powershell.exe`。
- **B（网络记录）**：与A相同的进程实例出现网络连接事件。
- **C（文件创建）**：该进程创建后缀为.exe的文件，且发生在B后；后缀不能证明文件结构有效或已经执行。
- **时间窗口**：例如A到C不超过10秒，仅为教学规则，不是通用EDR阈值。

### 声明式匹配：MATCH_RECOGNIZE
支持该语法的流式SQL引擎可表达类似逻辑。下述代码展示模式的**核心部分**，并非保证可直接运行的完整SQL，也不是某历史EDR的私有源码：

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
- `PARTITION BY`：按设备和进程实例划分，避免把无关进程拼接。
- `ORDER BY`：指定事件时间顺序；生产环境仍需乱序和迟到策略。
- `PATTERN (A B C)`：**不天然允许同一分区中任意插入其他事件**；跳过语义需按引擎明确处理。表中的Chrome事件属于另一分区，不会插入P-A的分区序列。
- `DEFINE`：事件条件；还需按引擎语法加入10秒窗口、匹配输出和跳过策略。完整流实现参考Apache Flink CEP。

### 底层：按Key保存部分匹配
```text
S0 --收到A--> S1 --收到B--> S2 --收到C且未超时--> 匹配
```
CEP引擎按关联键保存并发部分匹配和计时状态，负责转移、过期与清理。复杂模式常使用NFA或等价机制；不是消除了if-else，而是**工程化条件判断和状态管理**。

| 问题 | 手写if-else | CEP |
|---|---|---|
| 单事件条件 | 直接判断 | 可以做，但不必引入CEP |
| A→B→C及时间窗 | 自行保存状态/计时 | 声明式模式与窗口 |
| 大量实例并行匹配 | 自行维护分区状态 | 引擎分区与并行计算 |
| 迟到、乱序、重复 | 自行设计 | 取决于引擎的事件时间、水位线等机制 |

### 可运行实验：先把两阶段机制验证清楚
[实际源码detect_sequence](experiments/event_models.py)实现的是**进程条件→443网络事件，60秒窗**，不是上述三阶段SQL的完整实现。它按`host/boot/pid/start`分区，跳过无关事件，首次命中后消费状态，退出时清理；重复事件去重，冲突ID、未排序输入和状态预算不足明确报错。

在仓库根目录启动Python后运行：

```python
import sys
sys.path.insert(0, 'notes/edr/experiments')
from event_models import detect_sequence

base = dict(host='H1', boot='B1', pid=640, start=0)
records = [
    dict(base, id='E1', time=0, kind='process',
         image='powershell.exe', parent_image='winword.exe'),
    dict(base, id='E2', time=5, kind='network', port=443)
]
print(detect_sequence(records))
```

输出一条`NEEDS_REVIEW`，证据ID为`['E1','E2']`。不是“攻击已证实”。修改输入后，应得到：

| 改动 | 预期 |
|---|---|
| 网络事件属于另一PID、启动会话或创建时间 | 不匹配 |
| 时间为60秒 | 边界内匹配 |
| 时间为61秒 | 过期，不匹配 |
| 中间有同实例退出事件 | 清理状态，不匹配 |
| 输入事件时间倒退 | 拒绝处理，不伪装已支持乱序 |
| 缺少创建时间 | 身份不完整，拒绝拼接 |

[回归测试](experiments/test_experiments.py)包含这些情况。输入是人工归一化字典，不直接解析Sysmon XML；有限批次去重不等于无限流的留存方案，简单两阶段状态也不代替完整NFA。

## 审计
- 验证身份和跨重启边界：优先使用稳定实例ID，或host/boot/PID/创建时间；不要只用PID。
- 分开记录证据边与推断边；父关系不一定是实际创建动作，见[进程身份](process-identity.md)。
- 明确事件发生时间/到达时间、乱序策略、时间窗、跳过语义、重复与退出回收。
- 用正常Office插件与不同进程交错活动做反例，不能把命中等同恶意。

## 易错
- **事件归属不等于模式检测**：JOIN/Hash Map解决对象对应，CEP执行时序条件，威胁判断依赖规则语义和证据。
- **CEP不是机器学习**；规则由人定义。
- **PATTERN(A B C)不是任意三个事件凑齐**，还受分区、顺序、策略和窗口约束。
- **.exe后缀不等于有效可执行文件，更不等于执行证据**。
- 手写离线实验、2018年EQL示例、现代流SQL是不同表达与工程实现，不能混为某个年代产品统一做法。

关联：[EDR发展史](README.md) · [观测与检测](edr-observation-vs-detection.md) · [进程身份](process-identity.md) · [实验入口](experiments/README.md)

参考：[Flink CEP](https://nightlies.apache.org/flink/flink-docs-stable/docs/libs/cep/) · [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) · [EQL，2018](https://www.elastic.co/blog/getting-started-eql)
