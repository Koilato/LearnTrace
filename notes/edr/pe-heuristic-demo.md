# 静态 PE 启发式检测：最小 Demo（实验）

## 一句话
读取磁盘 PE 的节区、入口点与普通导入 API，用示例规则评分；仓库保留 **pefile 解析/纯函数评分版**与**Python 标准库解析版**的实际源码、合成输入和回归测试，均为可复现的教学用静态启发式 Demo，不是完整 EDR。

## 原理
读取字节 → 校验头部与边界 → 解析 PE32/PE32+ → 定位节区、入口点和导入 → 抽取特征 → 返回具体命中原因、分数与判断。两套实现都只读取文件，不加载或执行 EXE。

### 共同的教学规则

| 条件 | 分值 | 判定对象 |
|---|---:|---|
| 节区原始数据 ≥1024 字节且 Shannon 熵 ≥7.2 bit/byte | +20 | 每个符合条件的节区 |
| 节区同时可写、可执行 | +20 | 每个符合条件的节区 |
| 非零入口点所在节区不可执行 | +25 | 入口点节区 |
| 普通导入表含 `WriteProcessMemory` | +14 | API 名精确匹配且去重，各一次 |
| 普通导入表含 `CreateRemoteThread` | +18 | API 名精确匹配且去重，各一次 |

熵按实际原始数据计算，不计虚拟零填充。总分 ≥40 输出 `NEEDS_REVIEW`；这些权重与阈值是教学设置，不代表真实产品规则。两个导入 API 的组合只有 32 分，按本例阈值仍不告警，不应据此判断它们安全或恶意。

### 两套实现的接口与边界

| 项目 | pefile 版 | 标准库版 |
|---|---|---|
| 源码 | [根目录 `pe_heuristic_demo.py`](../../pe_heuristic_demo.py) | [`experiments/pe_heuristic_demo.py`](experiments/pe_heuristic_demo.py) |
| 解析与评分 | `parse_pe(bytes) → PEFeatures → score_features(features)`；固定 `pefile==2024.8.26`，评分为无文件依赖的纯函数 | `analyze()` 校验范围、解析节区和导入并评分；`rva_to_offset()` 转换 RVA，`entropy()` 计算字节分布，`signals` 保存命中原因 |
| 文件上限 | 64 MiB | 16 MiB |
| 低于 40 分 | `LOW_RISK`，仅表示低于示例阈值 | `NO_RULE_HIT`，实际表示未达到阈值；即使已有 32 分和命中信号，也返回此值 |
| 解析/输入失败 | 输入/依赖错误均在 stderr 输出 JSON `ERROR`，退出码 2，不产生风险判断 | stdout JSON `ANALYSIS_INCOMPLETE`，退出码 2，不按零分处理 |
| 扫描完成 | 返回 0，包括 `NEEDS_REVIEW` | 返回 0，包括 `NEEDS_REVIEW` |

**pefile 版**：入口点按 RVA 落入 `[VirtualAddress, VirtualAddress + max(VirtualSize, SizeOfRawData))` 定位；零入口点跳过该规则并给出提示，非零入口点未映射则报错。入口点可映射到节区的虚拟尾部，但虚拟补零不计入磁盘熵。截断、节区重叠及不完整导入解析等输入拒绝处理，其余解析警告保留在输出中。

**标准库版**：`rva_to_offset()` 要求映射唯一且有文件字节支撑，拒绝把补零内存区当成文件字节；非零入口点也必须满足这一条件。解析器限制为 1–96 个节区，导入描述符最多检查 256 项、每张导入查找表最多检查 4096 项，名称读取最多检查 512 字节；描述符、查找表和名称都必须在各自预算内遇到终止符。它拒绝重叠布局、坏 RVA、截断和部分不支持的特殊布局，这些失败表示覆盖不完整，不是恶意判断。

## 审计 / 复现实验
以下命令从仓库根目录执行，要求 Python ≥3.10。两套测试分别启动 Python 进程，避免两个同名 `pe_heuristic_demo` 模块在同一进程中混用。

### 1. pefile 版：评分边界、解析接口与 CLI

```bash
python -m venv .venv
# Linux/macOS；Windows 用 .venv\Scripts\activate
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m tests.run_experiment > experiment-results.local.json
python pe_heuristic_demo.py /path/to/sample.exe
```

无需外部样本即可复现 CLI（只生成、读取文件，不执行它）：

```bash
python -c "from pathlib import Path; from tests.pe_fixtures import make_pe; Path('sample.exe').write_bytes(make_pe(high_entropy=True, writable=True))"
python pe_heuristic_demo.py sample.exe
```

输出 JSON 含 SHA-256、特征、规则命中、总分、阈值及解析警告。

**2026-10-22 原始实测记录**：CPython 3.12.14，Linux x86_64 / glibc 2.39，pefile 2024.8.26；20 个测试全部通过，18 条输入/预期/实际记录全部匹配。该记录仅证明此环境的本地验证；CI 配置覆盖 Python 3.10、3.12、3.13，其实际结果以 Actions 为准。

| 确定性输入 | 预期 | 原始实测 |
|---|---|---|
| 常规布局合成 PE32 / PE32+ | 0，LOW_RISK | 一致 |
| 1023 字节、熵 8 / 1024 字节、熵略低于 7.2 | 0 / 0 | 一致 |
| 1024 字节、熵恰好 7.2 / 略高于 7.2 | 20 / 20 | 一致 |
| 高熵 + 可写可执行（合成 PE） | 40，NEEDS_REVIEW | 一致 |
| 不可执行入口点 + WriteProcessMemory（合成 PE） | 39，LOW_RISK | 一致 |
| 两个 API（PE32+） | 32，LOW_RISK | 一致 |
| 空文件、非 PE、节区截断 | InvalidPE，无风险判断 | 一致 |

[源码](../../pe_heuristic_demo.py) · [测试](../../tests/test_pe_heuristic_demo.py) · [合成 PE 生成器](../../tests/pe_fixtures.py) · [实测原始记录](../../tests/experiment-results.json)。记录包含输入参数、样本/源码 SHA-256、预期与实际值、完整测试输出及环境；运行 `python -m tests.run_experiment` 可重建，时间与耗时允许变化。7.2 精确边界使用合成特征；字节熵另测 0/7/8，PE 解析另用结构化合成文件验证。此前对话声称的运行结果仍未追溯核验。

### 2. 标准库版：PE 结构解析与 EDR 机制实验

此版本只使用 Python 标准库，不需要安装 `pefile`：

```sh
python -m unittest discover -s notes/edr/experiments -p 'test_*.py' -v
python notes/edr/experiments/fixtures.py --out /tmp/learntrace-pe-fixtures
python notes/edr/experiments/pe_heuristic_demo.py /tmp/learntrace-pe-fixtures/high_entropy_rwx.bin
```

Windows 将 `/tmp/learntrace-pe-fixtures` 换成新的测试目录；生成器使用独占创建，重复运行不会覆盖已有同名文件。

| 合成输入 | 计算 | 预期输出 |
|---|---|---|
| low_signal.bin | 无规则命中 | 0，NO_RULE_HIT |
| high_entropy_rwx.bin | 高熵20 + RWX20 | 40，NEEDS_REVIEW |
| nonexec_entry.bin | 高熵20 + 非执行入口25 | 45，NEEDS_REVIEW |
| two_imports.bin | 导入14 + 导入18 | 32，NO_RULE_HIT |
| 截断或不支持的布局 | 无法完成解析 | ANALYSIS_INCOMPLETE，退出码2 |

每次成功输出包含输入 SHA-256、原始特征、导入名称、信号、分数、判断和覆盖范围。完整实验集还覆盖 CPU 模拟、掩码扫描、IOC、进程身份、事件序列和响应状态；2026-11-06 的 Linux / CPython 3.13.5 原始验证记录包含 38 项通过测试、四份合成 PE 的 SHA-256 和验证边界，见[实验运行说明](experiments/README.md)、[验证记录](experiments/validation.md)、[合成输入生成器](experiments/fixtures.py)及[回归测试](experiments/test_experiments.py)。

## 易错
- 示例权重与阈值不代表真实产品规则；命中不能单独证明恶意行为，低于阈值不代表安全。标准库版的 `NO_RULE_HIT` 不意味着 `signals` 必为空。
- 这是现代 Python 对历史思路的教学重建，不把每项规则和接口倒推为 1990 年代产品标准。
- 两套实现只分析普通导入名称；不解析序号 API 的名称、不评分延迟导入、动态解析 API 或解包后的内存行为。导入表列出 API，不证明运行时调用过；多个相关信号可能重复计分。
- 解析器不是完整 PE 规范实现或 Windows 加载器校验器，不分析 TLS 行为、证书和完整装载过程；不同版本对补零 RVA 和特殊布局的拒绝边界不同。
- 测试数据只保证满足对应解析器的实验要求，合成 PE 未验证可被 Windows 加载，也没有运行它们，不能作为真实正常/恶意样本。
- 合成数据验证计算和失败路径，不证明真实检出率、误报率或生产可用性。
- 静态评分不包含终端遥测、行为关联和响应，也不监控解包 Stub。参见 [EDR 行为观测与检测](edr-observation-vs-detection.md)、[PE 加壳与解包](pe-packing-unpacking.md)。

关联：[启发式原理](heuristic-detection.md) · [地址转换](pe-addresses.md) · [节区权限](pe-sections-permissions.md) · [异常入口点](pe-entrypoint.md)。格式依据：[Microsoft PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)；解析接口：[pefile 文档](https://pefile.readthedocs.io/en/latest/modules/pefile.html)。
