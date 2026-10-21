# PE 中 FOA、RVA、VA 的区别（概念）

## 一句话
**FOA 是字节在磁盘文件中的位置；RVA 是位置相对程序内存映像基址的偏移；VA 是进程虚拟地址。**

## 原理
假设 `.text` 的文件起点 `PointerToRawData=0x400`，映像相对起点 `VirtualAddress=0x1000`；入口点 `RVA=0x1100`，实际加载基址为 `0x140000000`。

```text
文件中：起点 0x400 + (0x1100 - 0x1000) = FOA 0x500
内存中：实际基址 0x140000000 + RVA 0x1100 = VA 0x140001100
```

`FOA = PointerToRawData + (RVA - Section.VirtualAddress)` 仅适用于映射到文件原始数据的节区范围；`VA = 实际装载基址 + RVA`。ASLR 可能改变实际装载基址，使之不同于 PE 的首选 `ImageBase`。

## 审计
- 从磁盘读取入口点附近字节：先把 RVA 转成有效 FOA，再读取文件。
- 运行时检查内存地址：使用进程的真实映像基址计算 VA。
- 遇到仅存在于内存的补零范围或畸形节区时，不能机械地套用 FOA 公式。

## 易错
- `AddressOfEntryPoint` 是 RVA，不是 FOA，也不是绝对 VA。
- `ImageBase` 是**首选**基址，未必是实际加载地址。
- 同一内容在磁盘文件中的排列与内存映像中的排列可能不同。

上级：[PE 文件结构](pe-file-basics.md) · 相关：[入口点](pe-entrypoint.md)
