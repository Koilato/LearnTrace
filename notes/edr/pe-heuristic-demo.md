# 静态 PE 启发式检测：最小 Demo（实验）

## 一句话
通过节区熵、权限、入口点和标准导入表加权，重建静态启发式模块；本目录已包含[实际源码](experiments/pe_heuristic_demo.py)、[合成输入生成器](experiments/fixtures.py)和[回归测试](experiments/test_experiments.py)，不再只有接口约定。

## 原理
读取字节 → 校验头部与边界 → 解析 PE32/PE32+ → RVA 转文件偏移 → 抽取特征 → 返回具体信号和分数。

| 教学规则 | 权重 | 判定对象 |
|---|---:|---|
| 原始节区至少 1024 字节且 Shannon 熵 ≥ 7.2 | 20 | 每个符合条件的节区 |
| 节区同时可写、可执行 | 20 | 每个符合条件的节区 |
| 非零入口点所在节区没有执行标志 | 25 | 入口点节区 |
| 标准导入表出现 WriteProcessMemory | 14 | API 名字去重后计分 |
| 标准导入表出现 CreateRemoteThread | 18 | API 名字去重后计分 |

累计 ≥40 输出 `NEEDS_REVIEW`；否则为 `NO_RULE_HIT`，不是“安全”。这些阈值是教学设置，非厂商规则。两个导入的组合只有 32 分，按本例阈值仍不告警，不应误读为这两个 API 安全或恶意。

核心逻辑可以直接在源码中定位：`analyze()` 校验范围、解析节区和导入；`rva_to_offset()` 拒绝把补零内存区当成文件字节；`signals` 保存命中原因；`entropy()` 计算字节分布。解析失败返回 `ANALYSIS_INCOMPLETE`，不会偷偷按零分处理。

## 审计 / 复现实验
从仓库根目录执行：

```sh
python -m unittest discover -s notes/edr/experiments -p 'test_*.py' -v
python notes/edr/experiments/fixtures.py --out /tmp/learntrace-pe-fixtures
python notes/edr/experiments/pe_heuristic_demo.py /tmp/learntrace-pe-fixtures/high_entropy_rwx.bin
```

| 合成输入 | 计算 | 预期输出 |
|---|---|---|
| low_signal.bin | 无规则命中 | 0，NO_RULE_HIT |
| high_entropy_rwx.bin | 高熵20 + RWX20 | 40，NEEDS_REVIEW |
| nonexec_entry.bin | 高熵20 + 非执行入口25 | 45，NEEDS_REVIEW |
| two_imports.bin | 导入14 + 导入18 | 32，NO_RULE_HIT |
| 截断或不支持的布局 | 无法完成解析 | ANALYSIS_INCOMPLETE，退出码2 |

每次输出包含输入 SHA-256、原始特征和信号；环境及实测范围见[验证记录](experiments/validation.md)。测试数据只保证满足本解析器的实验要求，没有验证 Windows 可以加载，不能作为真实正常/恶意样本。

## 易错
- 这里使用现代 Python 标准库重建历史思路，不把此实现的每项规则和接口倒推为 1990 年代产品标准。
- 源码只读取文件，不执行 PE，不监控解包 Stub；动态观测见[观测与检测](edr-observation-vs-detection.md)。
- 解析器并非完整 PE 规范实现：不分析 TLS、延迟导入、动态解析、证书、壳和完整装载过程；拒绝重叠布局及部分特殊文件是覆盖边界，不是恶意判断。
- 标准导入表列出 API，并不证明运行时调用过。多个相关信号可能重复计分。
- 合成数据验证计算和失败路径，不证明真实检出率、误报率或生产可用性。

关联：[启发式](heuristic-detection.md) · [地址转换](pe-addresses.md) · [节区权限](pe-sections-permissions.md) · [入口点](pe-entrypoint.md)

依据：[Microsoft PE 格式](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)。
