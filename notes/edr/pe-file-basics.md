# PE 文件是什么？（概念）

## 一句话
PE（Portable Executable）是 Windows EXE、DLL 等文件使用的一种组织格式：**文件头说明如何装载，节区表说明内容在哪，节区数据是真正的内容**。

## 原理
把 EXE 想成一本书：文件头是说明书、节区表是目录、节区数据是正文。

```text
example.exe
├── DOS Header：文件以 MZ 开始；e_lfanew 指向 PE 头
├── DOS Stub：早期 DOS 兼容代码
├── PE/NT Headers
│   ├── PE Signature：PE\0\0
│   ├── COFF File Header：Machine（CPU 架构）、节区数量
│   └── Optional Header：ImageBase、AddressOfEntryPoint 等
├── Section Table：每个节区的位置、大小、属性
└── Section Data：机器指令、常量、已初始化数据等
```

**例子**：C 程序 `int main(){return 10;}` 编译后，CPU 指令通常位于 `.text`；字符串常量可能位于 `.rdata`；已初始化可写变量可能位于 `.data`。这些是约定而非必然规则。

## 审计
1. 读取文件头前两个字节，通常为 `4D 5A`（MZ）。
2. 读取文件偏移 `0x3C` 处的 `e_lfanew`；根据它找到 `PE\0\0`。
3. 从节区表获取各区域位置、大小和权限，结合内容分析异常。

## 易错
- PE **不是**程序源代码，节区数据中的代码已经是机器指令。
- “Optional Header” 对普通 PE 映像实际是必要的。
- 文件里的字节偏移不等于程序在内存里的地址，见 [FOA/RVA/VA](pe-addresses.md)。
- 想知道为什么要分节区，见 [节区和权限](pe-sections-permissions.md)。

上级：[知识索引](knowledge-index.md) · 后续：[入口点](pe-entrypoint.md)
