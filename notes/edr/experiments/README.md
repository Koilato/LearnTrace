# EDR 机制实验：可运行范围与验证边界

## 一句话
用无害合成输入验证算法的状态、输出和失败条件；不执行恶意样本，不安装驱动，不改变主机网络策略。

## 原理
这些源码是**现代 Python 对历史机制的教学重建**，不是当年产品源码。使用 Python 3.10+ 标准库，不需要第三方依赖；本次实际测试环境与结果见 [验证记录](validation.md)。

| 文件 | 输入与行为 | 不能声称的能力 |
|---|---|---|
| [cpu_emulator.py](cpu_emulator.py) | 解释固定的六类 16 位指令编码，输出逐步寄存器和内存 | 完整 x86、DOS 或 Windows 仿真 |
| [event_models.py](event_models.py) | 掩码匹配、审计 XML 条件、进程身份、离线序列、响应状态转移 | 真实传感器、完整 OpenIOC/CEP 引擎、真正隔离 |
| [pe_heuristic_demo.py](pe_heuristic_demo.py) | 只读解析 PE32/PE32+，输出信号、分数及 SHA-256 | Windows 装载器、真实恶意率或生产杀毒引擎 |
| [fixtures.py](fixtures.py) | 生成四份确定性 PE 结构测试数据 | 经 Windows 验证可运行的程序、正常/恶意标签 |
| [test_experiments.py](test_experiments.py) | 回归断言及 CLI 失败状态 | 大规模性能和真实攻击覆盖率 |

## 审计 / 运行
从仓库根目录执行：

```sh
python -m unittest discover -s notes/edr/experiments -p 'test_*.py' -v
python notes/edr/experiments/cpu_emulator.py --budget 8
python notes/edr/experiments/cpu_emulator.py --budget 9
python notes/edr/experiments/fixtures.py --out /tmp/learntrace-pe-fixtures
python notes/edr/experiments/pe_heuristic_demo.py /tmp/learntrace-pe-fixtures/high_entropy_rwx.bin
```

Windows 将 `/tmp/learntrace-pe-fixtures` 换成一个尚未存有同名文件的测试目录。生成器使用独占创建，不覆盖已有文件；第二次重复运行会拒绝覆盖。

预期：8 步为 `BUDGET_EXHAUSTED`、9 步为 `MATCH`；高熵 RWX 样例为 40 分、`NEEDS_REVIEW`；低信号样例为 0 分、`NO_RULE_HIT`；解析错误为 `ANALYSIS_INCOMPLETE`，CLI 退出码 2。

## 易错
- 8 步未看到 ABC，不等于没有 ABC；规则未命中，不等于文件安全。
- 示例模型消费已归一化事件：映像名称为 basename，时间单位为秒，进程键含 host/boot/pid/start。它不直接读取 Sysmon XML。
- 序列实验只有两阶段、首个命中后消费状态；不是支持任意并发路径的 NFA。去重集合适用于有限离线批次，不能不加留存策略直接用于长期流。
- XML 匹配器只面向小型可信测试数据；长度与 DTD 检查不等于完整不可信 XML 安全实现。
- PE 解析器限制文件、节区、描述符、导入项和名称大小，拒绝部分特殊布局；不支持延迟导入、运行时 API 解析、TLS 行为和完整装载器语义。
- Windows 回调、AMSI、API Hook 和 eBPF 的笔记片段未在相应系统中编译/加载，不能计入本目录测试通过范围。

上级：[知识索引](../knowledge-index.md) · [PE 实验说明](../pe-heuristic-demo.md)
