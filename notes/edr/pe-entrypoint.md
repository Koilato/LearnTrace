# PE 入口点与异常入口点（概念）

## 一句话
入口点是程序映像开始执行的指定位置。**如果入口点落在一个没有声明执行权限的节区，就属于值得调查的 PE 结构异常，但不等于已确认恶意。**

## 原理
- `OptionalHeader.AddressOfEntryPoint` 保存入口点的 **RVA**（相对内存映像基址的地址），不是文件偏移。
- 用 RVA 查询 [节区表](pe-sections-permissions.md)，找到对应节区；再检查 `Characteristics & 0x20000000` 是否非零。
- 示例：`.text` 的 RVA 范围是 `0x1000–0x2FFF`，权限 R-X；`.data` 是 `0x3000–0x3FFF`，权限 RW-。入口点 `0x1500` 在 `.text`，通常合理；`0x3500` 在 `.data`，属于静态可疑信号。

```python
entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
for section in pe.sections:
    start = section.VirtualAddress
    end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
    if start <= entry < end:
        if not (section.Characteristics & 0x20000000):
            print("可疑：入口点所在节区未标记为可执行")
        break
```

以上区间计算是教学近似；稳健解析还要处理对齐、重叠节区、畸形头等。

## 审计
1. 解析 PE Header，读入口点 RVA。
2. 查找包含入口点的节区。
3. 检查节区执行权限，结合其他特征调整风险评分。

## 易错
- 入口点**不一定**是 C 的 `main()`；启动代码可能先做初始化。
- 加壳程序通常也有正常可执行的解包入口；**加壳 ≠ 入口点不可执行**。
- PE 标记权限未必等于运行时最终页权限，单个特征不能定罪。
- `ImageBase + RVA` 得到的 VA 假设用的是实际装载基址，见 [地址体系](pe-addresses.md)。

上级：[知识索引](knowledge-index.md) · 关联：[节区权限](pe-sections-permissions.md)
