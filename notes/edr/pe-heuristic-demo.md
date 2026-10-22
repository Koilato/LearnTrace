# 静态 PE 启发式检测：最小 Demo（实验）

## 一句话
读取磁盘 PE 的节区、入口点与导入 API，用示例规则评分；这是**可复现的教学用静态启发式 Demo，不是完整 EDR**。

## 原理
`parse_pe(bytes) → PEFeatures → score_features(features) → 分数 / 命中依据 / 判断`：解析使用固定版本 `pefile`，评分是无文件依赖的纯函数；扫描过程不加载或执行 EXE。

| 条件 | 分值 |
|---|---:|
| 节区原始数据 ≥1024 字节且 Shannon 熵 ≥7.2 bit/byte | +20/节区 |
| 节区同时可写、可执行 | +20/节区 |
| 入口点所在节区不可执行 | +25 |
| 普通导入表含 `WriteProcessMemory` / `CreateRemoteThread` | +14 / +18，各一次 |

总分 ≥40 输出 `NEEDS_REVIEW`，否则 `LOW_RISK`（仅表示低于示例阈值，不代表安全）。API 名精确匹配且去重；熵按实际原始数据计算，不计虚拟零填充。入口点按 RVA 落入 `[VirtualAddress, VirtualAddress + max(VirtualSize, SizeOfRawData))` 定位；零入口点跳过该规则并给出提示，非零入口点未映射则报错。

## 审计
仓库根目录，Python ≥3.10：

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

输出 JSON 含 SHA-256、特征、规则命中、总分、阈值及解析警告；扫描成功返回 0（包括需审核），输入/依赖错误返回 2，stderr 输出 `ERROR`，不产生风险判断。文件上限 64 MiB；截断、节区重叠及不完整导入解析等输入拒绝处理。

**2026-10-22 本次实测**：CPython 3.12.14，Linux x86_64 / glibc 2.39，pefile 2024.8.26；20 个测试全部通过，18 条输入/预期/实际记录全部匹配。仅此环境已本地验证；CI 配置覆盖 Python 3.10、3.12、3.13，其结果以 Actions 为准。

| 确定性输入 | 预期 | 实际 |
|---|---|---|
| 常规布局合成 PE32 / PE32+ | 0，LOW_RISK | 一致 |
| 1023 字节、熵 8 / 1024 字节、熵略低于 7.2 | 0 / 0 | 一致 |
| 1024 字节、熵恰好 7.2 / 略高于 7.2 | 20 / 20 | 一致 |
| 高熵 + 可写可执行（合成 PE） | 40，NEEDS_REVIEW | 一致 |
| 不可执行入口点 + WriteProcessMemory（合成 PE） | 39，LOW_RISK | 一致 |
| 两个 API（PE32+） | 32，LOW_RISK | 一致 |
| 空文件、非 PE、节区截断 | InvalidPE，无风险判断 | 一致 |

[源码](../../pe_heuristic_demo.py) · [测试](../../tests/test_pe_heuristic_demo.py) · [合成 PE 生成器](../../tests/pe_fixtures.py) · [实测原始记录](../../tests/experiment-results.json)。记录包含输入参数、样本/源码 SHA-256、预期与实际值、完整测试输出及环境；运行 `python -m tests.run_experiment` 可重建，时间与耗时允许变化。7.2 精确边界使用合成特征；字节熵另测 0/7/8，PE 解析另用结构化合成文件验证。此前对话声称的运行结果仍未追溯核验。

## 易错
- 示例权重与阈值不代表真实产品规则；命中不能单独证明恶意行为，合成样本也不能证明真实检测率或误报率。
- 只分析普通导入名称；不解析序号 API 的名称、不评分延迟导入、动态解析 API 或解包后的内存行为；解析器不是完整 Windows 加载器校验器，合成 PE 未进行运行兼容性验证。
- 静态评分不包含终端遥测、行为关联和响应。参见 [EDR 行为观测与检测](edr-observation-vs-detection.md)、[PE 加壳与解包](pe-packing-unpacking.md)。

关联：[启发式原理](heuristic-detection.md) · [节区权限](pe-sections-permissions.md) · [异常入口点](pe-entrypoint.md)。格式依据：[Microsoft PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)；解析接口：[pefile 文档](https://pefile.readthedocs.io/en/latest/modules/pefile.html)。
