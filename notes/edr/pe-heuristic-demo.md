# 静态 PE 启发式检测：最小 Demo（实验）

## 一句话
通过 PE 节区熵、权限、入口点和导入 API 进行加权打分，模拟早期杀毒软件中的**静态启发式模块**，而不是完整 EDR。

## 原理
```text
读取 PE → 解析节区/入口点/导入表 → 计算特征 → 规则加权 → 低风险/需审核
```

```python
score = 0
for section in pe.sections:
    if len(section.raw_data) >= 1024 and entropy(section.raw_data) >= 7.2:
        score += 20
    if section.writable and section.executable:
        score += 20
if entrypoint_section is not None and not entrypoint_section.executable:
    score += 25
if "WriteProcessMemory" in imported_apis:
    score += 14
if "CreateRemoteThread" in imported_apis:
    score += 18
if score >= 40:
    verdict = "NEEDS_REVIEW"
```

## 审计 / 复现实验
先运行 `python pe_heuristic_demo.py normal.exe`，再用测试样本对比规则命中。这里的文件名是接口约定；**本知识库目前没有提交对应源码，也没有独立核验此前对话中声称的运行结果**。应在补入实际脚本和测试输出后，再将其标为“已复现”。

建议核对：
1. 原始 PE：入口点位于可执行节区，检查正常样本是否误报。
2. 人为构造高熵且入口点无执行权限的 PE：是否命中高熵 + 异常入口点规则。
3. 记录测试文件 SHA-256、Python 版本、阈值和输出，保证可复现。
4. 不执行未知 PE 或故意破坏的测试 PE，仅进行静态解析。

## 易错
- 构造样本只验证规则是否触发，**不能证明真实恶意软件检测率**。
- 权重和 7.2 阈值都是教学示例，非行业统一标准。
- “静态扫描可运行”与“完整 EDR 可运行”不同，后者还需终端遥测、行为关联和响应。

关联：[启发式原理](heuristic-detection.md) · [节区权限](pe-sections-permissions.md) · [异常入口点](pe-entrypoint.md)
