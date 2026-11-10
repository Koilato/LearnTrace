# HIPS：把有状态规则接到真实操作的控制点（N05）

## 一句话
HIPS 在受控操作生效前综合主体、目标和状态作决定；它在2000年代就可能具有关联能力，不能被简化为只看孤立API的工具。

## 原理
[Cisco 2005年Packet，第48页](https://www.cisco.com/c/dam/en_us/about/ac123/ac114/downloads/packet/packet/may05/pdfs/packetQ2-05.pdf)描述了文件、网络、配置与执行空间拦截器，以及关联、状态、规则引擎和允许/拒绝决定。这是当年产品结构依据，以下规则则为教学重建，不是其源码。

痛点是等待新病毒特征可能太晚，因此把检查放到实际运行路径：请求到拦截点 → 读取主体与对象 → 查询状态和规则 → 允许时继续原调用，拒绝时通过该接口支持的方式返回失败。

```python
received = set()

def policy(e):
    p = e['instance']       # 此处假定已由传感器区分进程实例
    if e['op'] == 'NET_RECEIVE':
        received.add(p)
    deny = (e['role'] == 'web-server' and p in received
            and e['op'] == 'CREATE_PROCESS'
            and e['target'].lower() == 'cmd.exe'
            and not e['approved_exception'])
    if e['op'] == 'EXIT':
        received.discard(p)
    return 'DENY' if deny else 'NO_DENY_BY_THIS_RULE'
```

这里特意不用 `ALLOW` 表示全部安全：这一条规则没有拒绝，不代表其他规则或操作系统授权检查已经通过。目标为已解析映像的basename，不能用用户提交的路径文字直接假装可信身份。

| 步骤 | 输入 | 状态及输出 |
|---|---|---|
| 1 | Web进程P收到网络输入 | received加入P，无拒绝 |
| 2 | P请求创建cmd.exe | 条件成立，DENY |
| 3 | 管理进程Q做同样请求 | 没满足本规则，不代表全局许可 |
| 4 | P退出 | 清除状态，防止实例残留 |

当时的工程落地还包括策略管理、例外、日志以及内核/用户态拦截的适配。不同产品机制不同；Vista之后的回调接口不能解释所有更早产品。

## 审计
用正常CGI调用命令解释器作反例：它也可能先接收网络请求再启动cmd，规则因此误阻断。加入业务例外需要明确对象与生效范围；简单记录“进程生命周期内曾收包”会让长寿命服务长期处于可疑状态，生产规则需要更细关系或时间范围。

本页是决策逻辑，不是实际阻断器，也未在2005年产品中复现。真正拦截要使用对应操作系统控制语义，见[Windows采集与控制](windows-telemetry.md)。

## 易错
- 有状态HIPS不是现代EDR之前完全没有关联的阶段。
- 阻断能力与历史调查能力不同：允许的动作可能组成攻击，拦截日志不一定保留全部上下文。
- `DENY` 字符串只有被控制路径解释执行才会阻断，离线日志规则无法回到过去否决操作。

关联：[沙箱](sandbox-api-monitoring.md) · [远程取证](remote-forensics-ioc.md) · [历史主线](README.md)
