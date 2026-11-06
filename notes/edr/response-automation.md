# 自动调查与响应：扩展证据、创建任务、确认效果（N17—N18）

## 一句话
自动调查把可重复的排查步骤写成程序；真正响应还要经过权限、系统控制和结果核对，任务已发送不等于攻击已阻断。

## 原理
### 历史定位
[微软2018年产品说明](https://www.microsoft.com/en-us/security/blog/2018/11/15/whats-new-in-windows-defender-atp/)已经描述自动调查与内存修复。因此2020—2023章讲的是整合与扩展，不是自动响应首次出现；固定工作流不依赖LLM。

### 调查怎样自动扩大
输入：E10为H1/P3写出已确认恶意哈希BAD的文件，E11是P3外联，E20为H2/P8涉及同一哈希。以下是对已采集记录的教学遍历：

```python
todo, visited, evidence = [('H1','P3')], set(), []
while todo:
    key = todo.pop()
    if key in visited:
        continue
    visited.add(key)
    for e in records:
        if (e['device'],e['process']) != key:
            continue
        evidence.append(e['id'])
        if e.get('sha256') == BAD:
            todo.extend((r['device'],r['process']) for r in records
                        if r.get('sha256') == BAD)
```

先取E10/E11；E10提供扩展依据，再查询H2/P8取得E20。保留visited避免循环。生产实现使用索引、分页与范围限制，不能无界遍历所有数据。同一文件出现不是该进程已经执行文件的证明，也不是同一次攻击的充分证明。

### 响应任务必须与OS效果分开

```text
queued → accepted → reported → verified
                 超时 → unknown
                 失败 → failed
```

[response_step](experiments/event_models.py)是已测试的离线状态模拟，不执行隔离。`accepted`只表示Agent接收；`reported`表示Agent报告应用；`verified`需要额外有效策略状态证据。调用前必须验证任务ID、设备、授权与消息来源；同一任务终态不因迟到回执回退，重试创建新任务。

| 输入 | 原状态 | 新状态 |
|---|---|---|
| accepted回执 | queued | accepted，不是成功隔离 |
| applied回执 | accepted | reported |
| 仅有超时 | reported | unknown，不假装失败或成功 |
| 对应有效策略证据 | reported | verified |
| 迟到accepted | verified | 保持verified |

真实网络隔离可以通过WFP等控制路径装载规则，保留必要管理通道并限制其余通信。[WFP架构](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-architecture-overview)区分策略管理和实际过滤。验证规则存在也不保证覆盖全部层、已有连接、IPv6、隧道及依赖，必要时验证实际通信效果。

## 审计
教学时间线：0秒恶意进程开始，3秒告警，15秒确认，22秒装载隔离，23秒回执。前22秒可能已经有数据传出。终止进程不清除全部持久化；隔离文件不等于清除已载入内存；网络隔离不撤回已泄露数据。高影响动作须保留批准、对象身份、可回退信息和执行证据。

## 易错
- 异步EDR响应与操作生效前的同步拦截有不同时间保证。
- 已测试的是状态逻辑，不是实际WFP部署或终端隔离效果。
- 超时表示缺少完成证据，不应把告警直接关闭为已解决。

关联：[HIPS](hips-stateful-policy.md) · [进程身份](process-identity.md) · [AI调查](ai-assisted-investigation.md) · [历史主线](README.md)
