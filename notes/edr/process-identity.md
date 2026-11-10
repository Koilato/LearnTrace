# 进程身份：PID复用、迟到事件与父关系（N10）

## 一句话
先识别哪一次进程生命周期，再关联事件；记录父进程不保证就是实际发起创建的进程。

## 原理
PID640的旧进程从10:00存活到10:01，新进程在10:03复用640。旧进程10:00:20的网络记录10:04才上传，按“当前PID640”查表就会归错。

一种教学身份键为 `host + boot + pid + start_time`；有稳定实例ID时直接使用。启动会话防止跨重启混淆，创建时间精度和时钟校正仍需检查。

```python
matches = [p for p in lifetimes
    if (p['host'], p['boot'], p['pid']) == (host, boot, pid)
    and p['start'] <= event_time
    and (p['end'] is None or event_time < p['end'])]
instance = matches[0]['instance'] if len(matches) == 1 else None
```

完整[resolve_process](experiments/event_models.py)与[测试](experiments/test_experiments.py)使用同样逻辑。查询应采用事件发生时间，而不是上传到达时间；前提是事件与生命周期时间源可比较。

| 输入 | 候选 | 结论 |
|---|---|---|
| 10:00:20，PID640 | 旧生命周期 | OLD |
| 10:03:20，PID640 | 新生命周期 | NEW |
| 漏采旧进程退出，两个窗口均覆盖10:03:20 | 两个候选 | 未知，不强行拼接 |

### 父关系不等于创建动作
微软[PS_CREATE_NOTIFY_INFO说明](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info)明确区分ParentProcessId与CreatingThreadId.UniqueProcess。

```text
parent=200, creator=100, child=300
→ parent_of(200,300)
→ created_by(300,100)
```

只有父字段的日志应称为“记录父关系”，不能证明200调用了创建。父PID和创建者PID也要分别解析为当时的实例，不能对两者查当前PID表。

## 审计
Sysmon的ProcessGuid是传感器提供的关联标识，不是所有Windows组件都提供的通用内核GUID。跨源关联需要证明映射；一条源缺字段时保留未知。测试包含PID复用、不同host/boot/start、迟到旧事件及重叠窗口。

## 易错
- 同一实例的两条事件能证明归属，不能自动证明前一个动作导致后一个动作。
- 时间邻近、文件同路径、同用户名不等于同一对象或同一攻击。
- 简单生命周期匹配不能自动解决时间回拨、漏采和数据精度差异。

关联：[Windows采集](windows-telemetry.md) · [CEP](cep-event-patterns.md) · [知识索引](knowledge-index.md)
