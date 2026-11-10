# CPU 模拟：让解密过程发生在扫描器自己的内存中（N04）

## 一句话
模拟器逐条解释样本指令、更新虚拟寄存器与内存，再对展开内容扫描；预算不足、指令不支持和正常停止都不能证明样本安全。

## 原理
### 1990 年代为什么需要它
[Symantec 参与者的历史回顾](https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&DocumentKey=7069cb99-e833-4b38-876f-cf657c7deca0&tab=librarydocuments)记载，1994 年逐家族编写 C/汇编多态检测模块难以扩展，后来把 Striker CPU 模拟扫描集成到引擎。新的通用部分是执行解密过程，展开以后仍可以使用已知字节特征，并不天然识别所有未知恶意行为。

### 输入：固定的无害16位指令片段
下面是裸代码测试布局，CS/DS基址固定为0、IP从0开始；不是完整 DOS COM 文件，不能直接交给操作系统执行。地址和字节采用十六进制。

```asm
0000  BE 10 00     MOV SI,0010h
0003  B9 03 00     MOV CX,3
0006  80 34 55     XOR BYTE PTR [SI],55h
0009  46          INC SI
000A  E2 FA        LOOP 0006h
000C  F4          HLT
0010  14 17 16     ; 三个数据字节，目标为 ASCII ABC
```

IP 指向下一条指令；SI 指向当前数据；CX 是剩余循环次数。`14 XOR 55 = 41`、`17 XOR 55 = 42`、`16 XOR 55 = 43`。这些都是十六进制字节。

### 基本逻辑代码
完整可运行的[解释器](experiments/cpu_emulator.py)只有64字节虚拟内存，不调用原生代码。其循环中的核心分支为：

```python
# XOR byte [SI], imm8
memory[si] = read(si) ^ read(ip + 2)
ip += 3

# LOOP rel8
rel = read(ip + 1)
if rel >= 128:
    rel -= 256
cx, ip = (cx - 1) & 0xFFFF, ip + 2
if cx:
    ip = (ip + rel) & 0xFFFF
```

`FA` 解释为有符号 -6；LOOP 下一地址为 `000C`，因此跳到 `0006`。预算计数的是执行指令条数，不是循环轮数或字节数。

### 完整状态轨迹
以下 IP/SI/CX 使用十进制，数据区保持十六进制；IP 是该步骤完成后的下一条指令地址。

| 步骤 | 刚执行 | IP / SI / CX | 数据区 |
|---:|---|---|---|
| 1 | MOV SI | 3 / 16 / 0 | 14 17 16 |
| 2 | MOV CX | 6 / 16 / 3 | 14 17 16 |
| 3 | XOR | 9 / 16 / 3 | 41 17 16 |
| 4 | INC SI | 10 / 17 / 3 | 41 17 16 |
| 5 | LOOP | 6 / 17 / 2 | 41 17 16 |
| 6 | XOR | 9 / 17 / 2 | 41 42 16 |
| 7 | INC SI | 10 / 18 / 2 | 41 42 16 |
| 8 | LOOP | 6 / 18 / 1 | 41 42 16 |
| 9 | XOR | 9 / 18 / 1 | 41 42 43 |

第9步后扫描器已看到 ABC，提前返回 MATCH，此时没有执行最后的 INC、LOOP 和 HLT。所谓“命中”只证明人工标记出现，不证明恶意。

## 审计
从仓库根运行：

```sh
python notes/edr/experiments/cpu_emulator.py --budget 8
python notes/edr/experiments/cpu_emulator.py --budget 9
```

前者输出 `BUDGET_EXHAUSTED` 和 `414216`；后者为 `MATCH` 和 `414243`。测试另外验证未知操作码、越界、HLT、零预算与非法预算；见[实测范围](experiments/validation.md)。

## 易错
- 本实现只支持样例中的六种编码，不模拟完整标志寄存器、段机制、系统调用或操作系统；支持真实编码不等于完整兼容 x86。
- HLT 在本教学器中作为停止标记，不模拟硬件中断唤醒和所有权限语义。
- CPU 模拟解决部分内容不可见问题，不能补出网络、注册表或用户交互环境；这些需求推动[完整系统沙箱](sandbox-api-monitoring.md)。
- 指令预算是性能与覆盖的折衷，不能用预算耗尽来证明安全。

上级：[历史主线](README.md) · 前置：[特征扫描](signature-scanning.md) · 相关：[加壳解包](pe-packing-unpacking.md)
