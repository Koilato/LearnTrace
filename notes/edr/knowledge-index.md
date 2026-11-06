# EDR 学习知识索引

> 组织原则：**主线解释为什么出现技术，原子笔记解释技术自身，实验验证具体输入输出**。每篇独立可读，用相对链接引用，不把长篇文章复制到每个节点。

## 主线
- [EDR技术发展史](README.md)：七个阶段的痛点、实现增量、落地与遗留问题。
- [28节点DAG](history-dag.md)：沿用研究文章节点编号，明确前置依赖与实际文件位置；依赖不是发明先后。
- [实验入口](experiments/README.md)与[验证记录](experiments/validation.md)：区分已运行Python、数学核对和未编译系统片段。

## PE基础：保留原有阅读路径
1. [PE文件](pe-file-basics.md)：文件头、节区表和内容。
2. [节区与权限](pe-sections-permissions.md)：名称不决定R/W/X。
3. [入口点](pe-entrypoint.md)：入口RVA与节区声明。
4. [FOA/RVA/VA](pe-addresses.md)：文件与内存位置映射。
5. [加壳解包](pe-packing-unpacking.md)：Stub、内存恢复和OEP。
6. [启发式原理](heuristic-detection.md)与[PE实验](pe-heuristic-demo.md)：静态特征、规则、实际解析源码和失败状态。

## 从文件到运行时
| 专题 | 要回答的问题 | 实现/样例入口 |
|---|---|---|
| [特征扫描](signature-scanning.md) | 固定字节、通配符、多模式分别增加什么 | masked_offsets及跨块测试 |
| [CPU模拟](cpu-emulation.md) | 为什么8步不命中、9步命中 | 完整解释器、九步状态表 |
| [系统沙箱](sandbox-api-monitoring.md) | API请求怎样成为有结果的证据 | CreateFile包装片段与183反例 |
| [HIPS](hips-stateful-policy.md) | 如何把状态策略接到真实控制点 | Web进程规则与CGI误阻断 |
| [取证/IOC](remote-forensics-ioc.md) | 如何从一台扩展到其他主机 | XML、同一文件AND、A/B/C测试 |

## 从事件到检测
| 专题 | 要回答的问题 | 实现/样例入口 |
|---|---|---|
| [Windows采集](windows-telemetry.md) | 回调、ETW、过滤各能看到什么 | 字段复制、结果语义、快照与事件 |
| [进程身份](process-identity.md) | PID复用和父/创建者怎样处理 | 生命周期匹配、未知结果 |
| [缓冲与丢失](telemetry-buffering.md) | 为什么不能无限保存事件 | 有界队列、20.5秒容量示例 |
| [观测与检测](edr-observation-vs-detection.md) | 数据来源、关联和判定怎样分工 | 原有分层与误报反例 |
| [AMSI](amsi-runtime-content.md) | 谁把解码脚本送给扫描器 | 编码例子、接口结果分层 |
| [CEP](cep-event-patterns.md) | 怎样匹配同一实例的事件序列 | SQL/NFA原理与离线状态机 |
| [静态ML](ml-static-detection.md) | 切分、权重和阈值从哪里来 | 两轮提升树和误报算术 |

## 从调查到响应
- [自动调查与响应](response-automation.md)：证据扩展、任务状态、回执与实际效果。
- [XDR实体关联](xdr-entity-correlation.md)：账号/租户/文件映射与候选关系。
- [Linux eBPF](linux-ebpf-telemetry.md)：5.8+ ring buffer、exec语义、观测与阻断差别。
- [行为基线与图](behavior-baselines-graphs.md)：早于LLM的历史、数值与有证据的图边。
- [LLM与Agent](ai-assisted-investigation.md)：查询范围、真实证据、工具错误和受控迭代。

## 维护约定
- 原子笔记采用**一句话 / 原理 / 审计 / 易错**；主线、DAG和验证记录可以使用适合其目的的结构。
- 历史事实给原始资料或当时发布说明；现代接口文档只能证明契约，不能证明历史产品实现。
- 代码区分**历史原文、教学重建、接口片段**；运行状态区分**已测试、仅数值核对、尚未部署**。
- 现代Python版本是复现环境，不是历史产品语言；没有完整源码的片段不能标“已复现”。
- 保留已有短笔记，通过链接扩展；新增与修正先走独立分支/PR，不把主线变成代码合集。
- 构造输入、阈值和规则明确标注教学性质；异常、未命中、未知和恶意证实不能互换。
