# 特征码扫描：从逐字节比较到共享匹配状态（N01—N02）

## 一句话
特征扫描在可观察字节中查找已知模式；通配符解决局部变化，多模式算法减少重复扫描，格式解析限制搜索位置，但它们都不能自动获得尚未解密的内容。

## 原理
### 当时的痛点与实现
早期文件型病毒可以附加到不同宿主。宿主整体不同，附加代码仍可能含相同片段，因此完整文件相同与病毒片段相同是两个问题。参与者的[2007 年引擎回顾](https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&DocumentKey=7069cb99-e833-4b38-876f-cf657c7deca0&tab=librarydocuments)记录了字节扫描面对多态病毒的困难及后来的模拟路线。

下面用人工字节重建机制，不声称是某病毒真实签名。模式 `B8 ?? ?? CD 21` 的第 2、3 个字节可以变化，其他位置必须相同：

```python
pattern = bytes.fromhex('B80000CD21')
mask = [True, False, False, True, True]

def match_at(data, offset):
    if offset + len(pattern) > len(data):
        return False
    return all(not required or data[offset+j] == pattern[j]
               for j, required in enumerate(mask))
```

可运行完整函数见 [masked_offsets](experiments/event_models.py)。逻辑可用当时的 C/汇编实现；这里的 Python 只是重建语言。

| 输入 | 比较过程 | 输出 |
|---|---|---|
| `00 B8 FF 00 CD 21` | 偏移0不匹配；偏移1固定位置全同 | 偏移1命中 |
| `B8 01 00 CD 21` | 两个变化位置被忽略 | 偏移0命中 |
| `B8 FF 00 CD 10` | 最后一个固定字节不同 | 不命中 |

### 扫描器真正落地还需要什么
按需扫描负责枚举、读取文件；驻留扫描把匹配引擎接到特定文件操作路径。识别、阻断和修复是不同工作：修复被感染的宿主还要恢复原始入口和被修改字节，不能只有一个布尔匹配结果。

分块读取会产生边界问题：特征 `ABC`，两块分别是 `xxAB` 与 `Cyy`。分别扫描均失败；保留前一块最后 `m-1=2` 字节，与下一块一起扫描，才能得到全文件偏移2的匹配。实际规则可能有最大长度与锚点约束，不能默认所有扫描器都保留同样窗口。

### 特征数量增加以后
以 `ABCD / BC / CDE` 为模式集，输入 `XABCDE`。共享前缀转移和失败链接可以一次读取，分别返回 `BC@2`、`ABCD@1`、`CDE@3`。读到 E 时，`ABCD` 无 E 转移，保留仍然有用的后缀 CD，再接 E。搜索核心是：

```text
while 当前状态没有输入字符的转移且不是根:
    状态 = failure[状态]
状态 = 存在的转移，或根
输出这个状态及其失败链继承的匹配
```

这是 Aho–Corasick 类算法的机制，不代表所有历史杀毒引擎采用同一种算法。更长模式、文件区域锚点和格式解析也用于降低偶然命中。PE 的 RVA 转文件偏移见[地址转换](pe-addresses.md)，不要把 PE 节表套到 DOS COM 上。

## 审计
运行[回归测试](experiments/README.md)，检查固定字节改变、通配位置改变、空模式和跨块样例。匹配结果应保存位置及规则版本，便于解释为什么命中。大量特征的性能需要另测，不由三个人工模式证明。

## 易错
- 通配符增加容错也扩大误报面；上面的短片段可以是普通程序指令。
- 完整摘要识别相同文件，不等于家族识别或宿主感染识别；校验值变化也可能是合法更新。
- [MD5 RFC 1321](https://www.rfc-editor.org/rfc/rfc1321)发布于1992年，不应写成1980年代普遍采用；今天实验输出 SHA-256 是复现标识，不是历史检测能力。
- 当稳定明文只在运行中出现时，继续优化磁盘模式匹配仍看不到它，下一步是[CPU 模拟](cpu-emulation.md)。

上级：[历史主线](README.md) · [知识索引](knowledge-index.md)
