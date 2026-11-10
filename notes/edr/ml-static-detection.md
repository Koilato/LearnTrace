# 静态机器学习：切分和权重怎样从标签中产生（N16）

## 一句话
模型从训练样本学习特征组合，不是把人工风险分数换个名字；文件分类结果也不等于理解了攻击链。

## 原理
[2018年EMBER论文](https://arxiv.org/abs/1804.04637)提供静态PE特征、数据集及LightGBM提升树基线。这里只重建“训练怎样产生切分和叶值”，不用今天的大模型解释当年实现，也不复刻EMBER完整特征提取器。

教学训练集：熵为 `[5,6,7,7.5,7.8,7.9]`，标签为 `[0,0,1,1,0,1]`。熵7.8的正常样本故意保留，避免把高熵当作恶意定义。

以下完整小例子用两棵深度1的树，省略正则化、分箱和复杂树生长：

```python
from math import exp
x, y = [5, 6, 7, 7.5, 7.8, 7.9], [0, 0, 1, 1, 0, 1]
F, trees, eta = [0.0] * len(x), [], 0.5
cuts = [(a+b)/2 for a,b in zip(x, x[1:])]
for _ in range(2):
    p = [1/(1+exp(-f)) for f in F]
    g = [a-b for a,b in zip(p,y)]
    h = [a*(1-a) for a in p]
    candidates = []
    for cut in cuts:
        L = [i for i,v in enumerate(x) if v <= cut]
        R = [i for i,v in enumerate(x) if v > cut]
        GL, HL = sum(g[i] for i in L), sum(h[i] for i in L)
        GR, HR = sum(g[i] for i in R), sum(h[i] for i in R)
        gain = 0.5*(GL*GL/HL + GR*GR/HR - (GL+GR)**2/(HL+HR))
        candidates.append((gain, cut, -GL/HL, -GR/HR))
    _, cut, left, right = max(candidates)
    trees.append((cut, left, right))
    F = [f + eta*(left if v <= cut else right) for f,v in zip(F,x)]
print(trees)
print([round(1/(1+exp(-f)), 4) for f in F])
```

初始原始分数0，sigmoid为0.5。对二元交叉熵，梯度为`p-y`，二阶项为`p*(1-p)`；叶值为`-G/H`。在6.5切分，左侧G=1、H=0.5，叶值-2；右侧G=-1、H=1，叶值1；收益1.5。在7.65切分时两侧G均为0，收益0。算法据此选择6.5，而不是专家手写该阈值。

| 输入 | 第一轮叶值 | 第二轮叶值 | 两轮输出 |
|---|---:|---:|---:|
| 熵≤6.5 | -2 | 约-1.3679 | 0.1566 |
| 熵>6.5 | 1 | 约0.5427 | 0.6838 |

部署阈值0.6时，右侧四个样本全部告警，包括熵7.8的正常样本；改成0.7，三个恶意样本全部漏掉。阈值、样本分布和特征必须一起评价。

## 审计
本例可手算并单独运行；它不是大规模训练实验。真正落地需要固定特征版本，按时间划分训练/验证/测试，防止近重复样本泄漏，再根据业务误报预算选阈值。运行推断时沿每棵树走到叶节点，累加加权原始分数，再转换输出。

教学部署算术：100万个对象中100个恶意，检出率90%、正常对象误报率0.1%，约90个真阳性和1000个误报，告警准确率只有约8.3%。这不是EMBER测评结果。

## 易错
- sigmoid输出不是未经校准就可信的现场恶意概率。
- 文件熵、导入和结构特征仍会受压缩器、编译器和样本分布变化影响。
- 本例只用一个特征，不能据此声称真实检测率；不是完整LightGBM实现。
- [静态专家规则](pe-heuristic-demo.md)的权重由人设置，本例权重由损失函数和标签学习。

关联：[启发式](heuristic-detection.md) · [基线与图](behavior-baselines-graphs.md) · [历史主线](README.md)
