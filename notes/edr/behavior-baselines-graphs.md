# 行为基线与溯源图：两条早于LLM的分析路线（N21—N22）

## 一句话
基线比较活动与历史分布，溯源图追踪有证据的对象关系；二者都需要采集与身份基础，异常和可达路径都不是恶意事实本身。

## 原理
### 基线不是2023年才出现
[Denning 1987年论文](https://faculty.nps.edu/dedennin/publications/IDS%20model.pdf)已讨论审计记录、统计画像与误报。用现代Python手算一个教学窗口：某主机过去四个窗口的不同SMB目标数为2、4、4、6，当前为12。

```python
from math import sqrt
history, current = [2,4,4,6], 12
mean = sum(history)/len(history)
variance = sum((x-mean)**2 for x in history)/len(history)
z = (current-mean)/sqrt(variance) if variance > 0 else None
```

均值4、总体方差2、标准差约1.414，z约5.657。输出“偏离历史，应查看对应连接与进程”，不输出“横向移动已证实”。正常软件部署也可能增加目标数。四点历史仅供手算，不能作为稳定生产画像；实际还需要设备角色、周期、足够样本和污染控制。方差0不能直接除零或当作正常。

### 图需要真实的边
[HOLMES论文，2018预印本/2019发表](https://arxiv.org/abs/1810.01594)利用可疑信息流关联并生成高层调查图，不是LLM时代才有的能力。教学证据为：

```python
edges = [('P1','P2','spawn',1), ('P2','F1:v1','write',2),
         ('F1:v1','P3','execute',3), ('P3','I1','connect',4)]
todo, seen, selected = [('I1',5)], set(), []
while todo:
    node, latest = todo.pop()
    if (node,latest) in seen:
        continue
    seen.add((node,latest))
    for src,dst,kind,t in edges:
        if dst == node and t <= latest:
            selected.append((src,dst,kind,t))
            todo.append((src,t))
```

从I1反查，得到 `I1 ← P3 ← F1:v1 ← P2 ← P1`。F1带版本，避免同一路径不同内容被合并。各边必须先有对应创建、写入、执行、连接证据；删掉execute边，查询不能凭路径同名补出它。

### 图学习与图遍历的差别
图遍历按已知边取证；图模型还可以学习节点和邻居特征的组合。[GCN原论文](https://arxiv.org/abs/1609.02907)为2016预印本/2017发表，不应把HOLMES说成同一GNN实现。一个聚合步骤是：给邻接矩阵加单位阵，再按节点度归一化，用它乘节点特征，最后接可学习权重。

对链P1—F1—P2，初始特征`[1,0,0]`，按对称度归一化并聚合一次得到约`[0.5,0.4082,0]`。F1获得邻居信息，但此时还没训练分类器；若边或标签错了，也可能把错误信号传播给邻居。要称为学习，还必须给出损失、训练标签、参数更新和独立测试。

## 审计
基线检查采样窗口、分布、零方差和业务变更。图检查实体版本、边方向、时间、证据ID与缺口。这里的遍历与算术只重建基本机制，没有运行HOLMES或训练实际安全图模型。

## 易错
- 不同主体的异常不能任意累加成同一攻击。
- 文件被写出并有网络连接，不证明该文件内容被外传。
- 知识索引用DAG组织学习依赖，不表示所有终端实体图天然无环。

关联：[进程身份](process-identity.md) · [XDR](xdr-entity-correlation.md) · [ML](ml-static-detection.md) · [历史主线](README.md)
