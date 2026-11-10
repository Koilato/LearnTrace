# 验证记录：2026-11-06

## 已实际运行
环境：Linux，CPython 3.13.5。源码仅使用标准库，文档要求Python3.10+；本次没有分别在所有支持版本和Windows上运行。

从仓库根执行：

```sh
python -m unittest discover -s notes/edr/experiments -p 'test_*.py' -v
python -m compileall -q notes/edr/experiments
```

结果：**38项unittest全部通过**；5个Python源码文件语法编译通过。测试分布：CPU模拟6、掩码/块边界3、IOC4、事件序列/身份10、PE12、响应状态3。

| 验证主题 | 包含的边界 |
|---|---|
| CPU | 第8/9步、完整选定状态、未知指令、虚拟越界、停止、预算合法性 |
| 字节匹配 | 通配位置、固定位置、空模式、跨读取块漏检示例 |
| IOC | 同一文件AND、大小上下界、重复主机ID、DTD拒绝 |
| 关联/序列 | host/boot/pid/start隔离、时间窗边界、退出、乱序、重复冲突、状态预算、迟到旧事件、歧义 |
| PE | PE32/PE32+导入、熵、RWX、非执行入口、零入口、截断、重叠、补零区、坏RVA、CLI失败状态 |
| 响应 | 回执不等于验证、超时未知、迟到回执不回退终态 |

## 合成输入与输出
生成器只写PE结构的.bin测试数据，未验证为可装载程序，也没有运行它们。可用[fixtures.py](fixtures.py)在新目录重建。

| 文件 | 分数 | 输出 | SHA-256 |
|---|---:|---|---|
| low_signal.bin | 0 | NO_RULE_HIT | 557fa8a50b591a600ab8b09e84cd00d0104e40d6d6ab001ef510b4f2ea2c2d47 |
| high_entropy_rwx.bin | 40 | NEEDS_REVIEW | 76278b0192266b01a3189373faa4936b92ca0dfa8ac059d33e9259d3507530bb |
| nonexec_entry.bin | 45 | NEEDS_REVIEW | 0f6c079caf6d0b1324e7ede3ad456b72be13da2990fd68339f9362847a3476de |
| two_imports.bin | 32 | NO_RULE_HIT | f01dff839c1858562845e16c1c80fc77cd22d63741a60aa9d77f2155d9e6cf8b |

另外单独执行了[提升树小例子](../ml-static-detection.md)：两轮切分均为6.5，输出0.1566/0.6838；检查了[AMSI样例](../amsi-runtime-content.md)的Base64按UTF-16LE解码为`Write-Output 'EDR_DEMO_MARKER'`。这是数值与字符串核对，不是EMBER复现或AMSI系统集成测试，未计入38项单元测试。

## 没有验证，不能据此宣称完成
- 没有编译、签名、安装或压力测试Windows驱动；没有实际执行API Hook或AMSI provider。
- 没有构建/加载eBPF程序、测试verifier、发行版兼容性、事件丢失率或真实隔离效果。
- 没有调用生产EDR、真实LLM服务、邮箱或终端数据；响应函数只改变内存中的状态。
- 没有采集恶意样本、运行未知PE、测试真实检出率/误报率、训练完整EMBER/HOLMES/GCN模型。
- 没有声称重建当年私有产品源码；历史依据与现代教学实现分别标注。
- 这是一份本地验证记录，不等于GitHub Actions已经运行；本PR不增加或声称通过远程CI。

复现入口：[实验README](README.md) · [知识索引](../knowledge-index.md)
