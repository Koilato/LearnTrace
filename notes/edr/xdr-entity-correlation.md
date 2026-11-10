# XDR：跨域数据先对应实体，再讨论攻击链（N19）

## 一句话
XDR把邮件、身份、终端与云的线索组合为可调查关系；日志放在一起不代表对象已经对齐，时间相近也不证明因果。

## 原理
[微软2020年说明](https://www.microsoft.com/en-us/security/blog/2020/09/22/microsoft-announces-cloud-innovation-to-simplify-security-compliance-and-identity/)把跨身份、终端、邮件和云的整合列为方向。工程增量包括字段归一化、目录映射、时钟校正、可追溯关系和跨域查询，不是简单增加一个总告警数。

教学输入：M7在第10分钟将哈希H附件投递给租户T的alice；F9在第14分钟记录SID-A在终端写入哈希H。目录映射是已验证的前提，不由相似用户名猜测。

```python
directory = {('T','alice@example.test'): 'SID-A'}
mail = dict(id='M7', tenant='T', recipient='alice@example.test', hash='H', t=10)
file = dict(id='F9', tenant='T', sid='SID-A', hash='H', t=14)
matched = (mail['tenant'] == file['tenant']
           and directory.get((mail['tenant'],mail['recipient'])) == file['sid']
           and mail['hash'] == file['hash']
           and 0 <= file['t'] - mail['t'] <= 30)
if matched:
    relation = dict(source='M7', target='F9', kind='possible_delivery')
```

匹配输出是候选投递关系。接下来查询写入进程、文件版本和执行记录；同一合法安装包可以来自邮件，也可以来自下载站。只有这些字段，不能把边类型改成“邮件已导致执行”。

当租户不同、目录没有对应或时间不可比较时，不建立上述边；缺少映射不是自动证明两个账号不同，也可能是数据不足。共享邮箱、别名、重装设备和重复文件都需要额外处理。

## 审计
保存原事件ID、映射版本、关联条件、时间误差与关系置信类型。分开记录确定归属、目录映射与行为因果。权限同样跨域：调查者可以看终端日志，不代表能看所有用户邮件正文。

## 易错
- 相同哈希通常是内容匹配线索，不证明唯一来源、执行或同一活动。
- 联合查询没有创造底层传感器未观察到的事件。
- 本例是候选关系算法，不是产品连接器或完整XDR系统，也没有在真实租户数据上验证。

关联：[进程身份](process-identity.md) · [基线与图](behavior-baselines-graphs.md) · [历史主线](README.md)
