# 远程取证与 IOC：从一台主机的线索到批量复查（N06—N07）

## 一句话
先获取现场证据，再把可复查条件应用到其他主机；按需快照、痕迹分析和持续事件记录是不同能力，不能统一称作完整历史录像。

## 原理
### 当时在解决什么
找到恶意文件后，还需要知道服务是否指向它、进程是否加载它、其他机器是否留下相同痕迹。Mandiant [2013年OpenIOC说明](https://cloud.google.com/blog/topics/threat-intelligence/openioc-basics/)给出了可交换的调查条件及AND/OR组合；IOC用于辅助调查，不替代人的证据判断。

当时可实现的工作流程为：告警触发 → 远程收集进程/文件/注册表/内存证据 → 序列化审计记录 → 分析员选择条件 → 批量搜索其他主机。XML可以保存抽取的记录，不表示每次传输完整内存镜像。

### 对象边界决定逻辑是否正确
教学输入如下，不是可直接导入产品的OpenIOC格式：

```xml
<audits>
  <host id="A"><service name="MS 1atent time services"/></host>
  <host id="B"><file id="f1" name="bad.exe" size="6000"/></host>
  <host id="C">
    <file id="f2" name="bad.exe" size="12000"/>
    <file id="f3" name="good.exe" size="6000"/>
  </host>
</audits>
```

重建官方示例中的一部分条件：指定服务存在，或者存在**同一个文件**满足bad.exe且4096≤size≤10240。简化判断如下：

```python
service_hit = any(s.get('name') == 'MS 1atent time services'
                  for s in host.findall('service'))
file_hits = [f.get('id') for f in host.findall('file')
             if f.get('name') == 'bad.exe'
             and 4096 <= int(f.get('size')) <= 10240]
hit = service_hit or bool(file_hits)
```

完整[match_audit函数](experiments/event_models.py)另外保存证据ID并检查输入。现代Python重建的是当时即可表达的布尔与XML处理机制，不声称实现完整OpenIOC语法。

| 主机 | 结果 | 证据 |
|---|---|---|
| A | 命中 | 指定服务 |
| B | 命中 | f1同时符合名字与大小 |
| C | 不命中 | f2和f3分别符合一个条件，不能拼成同一文件 |

错误写法是分别对主机所有文件做两次 `any()`，再AND：那会把f2的名字与f3的大小拼接，错误命中C。

## 审计
[回归测试](experiments/test_experiments.py)验证A/B/C、上下界、重复主机ID和DTD拒绝。只用可信小型合成XML，不把这个简单解析器当作安全处理任意远程XML的完整方案。

现场采集时间也要记录：13:00运行并退出的进程，14:00枚举当前进程列表时已经不在。但其他痕迹仍可能辅助调查；不能因为快照没看到，就断言没有执行。

## 易错
- 文件存在、配置存在、执行发生是三种不同证据。
- 同一IOC在多台主机命中是扩展调查的理由，不自动证明同一攻击者或同一次活动。
- 现场快照没有自动保留已消失的事件；持续记录必须提前部署，而且仍有采集覆盖与丢失问题。

关联：[历史主线](README.md) · [Windows遥测](windows-telemetry.md) · [进程身份](process-identity.md)
