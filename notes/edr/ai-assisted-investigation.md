# LLM与Agent：让调查围绕真实查询结果迭代（N23—N24）

## 一句话
LLM负责提出取数意图和组织解释，执行器负责权限与查询，传感器记录仍是事实来源；多步Agent只是增加有边界的迭代，不自动获得可信证据或处置授权。

## 原理
### 历史锚点，而非未来能力推测
[2023年Security Copilot发布说明](https://blogs.microsoft.com/blog/2023/03/28/introducing-microsoft-security-copilot-empowering-defenders-at-the-speed-of-ai/)描述调查、查询和摘要，也承认生成内容可能错误。[2025年3月公告](https://www.microsoft.com/en-us/security/blog/2025/03/24/microsoft-unveils-microsoft-security-copilot-agents-and-new-protections-for-ai/)宣布专门Agent预览，Intune修复保留管理员批准。下文是教学设计，不是微软私有实现，也不宣称2026年所有EDR已具备自治能力。

### 单次查询怎样落地
模型不能直接获得任意SQL执行权。以下是未接入真实模型/数据库的接口骨架，`plan`已通过JSON结构校验，host和scope来自服务端授权上下文：

```python
queries = {'network': 'SELECT id,detail FROM events WHERE host=? AND process=? AND kind=?'}
if plan['query'] not in queries or plan['process'] not in scope:
    raise ValueError('query outside authorization')
rows = db.execute(queries[plan['query']], (host, plan['process'], 'net')).fetchall()
evidence = {str(row[0]): row[1] for row in rows}
context = {'question': question, 'executed_query': plan,
           'rows': evidence, 'coverage': coverage}
```

服务端绑定参数与只读权限，记录实际查询、时间范围、分页/截断、工具错误和覆盖信息。没有返回行与查询失败是两种状态；模型输出须保留这种差别。

具体问题：“P3是否外联并建立持久化？”只执行network查询，拿到E41“成功连接示例地址203.0.113.7:443”。合理结论是“有外联证据E41；尚未查询启动项/任务/服务，持久化未证实”。不能把未查的数据写成没有持久化。

### 多步Agent增加的状态

```text
原问题 + 已取证据 + 调用历史 + 允许工具 + 范围 + 预算
→ 模型选下一查询 → 执行器验证 → 查询 → 保存结果
→ 继续，或因完成/错误/预算而停止
```

| 轮次 | 查询 | 返回 | 合理的下一步 |
|---|---|---|---|
| 1 | network/P3 | E41外联 | 查看进程来源 |
| 2 | parent/P3 | E42记录父关系P2 | 不能假定P2就是真实创建者 |
| 3 | script/P2 | E43或工具错误 | 分析实际证据，或保存缺口 |

执行器需要防重复调用、超时、总预算和范围扩张审核。只有network/parent/script工具时，模型提出isolate不应被执行；高影响操作走[响应工作流](response-automation.md)。

## 审计
核查每条结论的事件ID确实存在且内容支持结论。仅检查“引用ID存在”不验证推理正确。命令行、文件名和日志文本可能由攻击者控制，作为数据而不是指令处理；工具白名单和权限必须由模型外部执行。审计还要记录模型/模板版本、输入覆盖和人工批准。

## 易错
- 2023年的辅助问答、固定自动调查、2025年的专门Agent不是同一机制的同义词。
- 查询生成器不能补齐未采集事件；预算耗尽不表示已排除攻击。
- 本页未调用真实LLM、生产数据库或隔离接口，不属于本次Python回归测试验证的产品能力。

关联：[基线与图](behavior-baselines-graphs.md) · [响应](response-automation.md) · [历史主线](README.md)
