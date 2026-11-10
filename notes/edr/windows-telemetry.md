# Windows 采集：接口通知怎样进入 EDR 历史记录（N08—N09、N12）

## 一句话
Agent把操作系统能提供的通知复制成有明确语义的事件，交给用户态存储与上传；接口名本身不保证覆盖所有行为，也不保证每个请求成功。

## 原理
### 时间边界
2013—2016年的EDR架构使用了更早已有的机制。[进程Ex回调](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)的最低客户端版本为Vista SP1。这里选择当时可用的接口说明路径，不使用后来新增的Ex2字段解释早期产品。

| 机制 | 可以观察/控制 | 不应推断 |
|---|---|---|
| 进程、线程回调 | 生命周期通知及可用上下文 | 后续全部执行细节 |
| 映像加载通知 | 映像映射 | 每条CPU指令、所有内存载荷 |
| ObRegisterCallbacks | 特定对象句柄创建/复制及权限处理 | 所有跨进程内存写入 |
| 注册表回调 | 对应操作的前后通知 | 请求必然成功 |
| Minifilter | 文件I/O路径与完成结果 | 请求字节数等于完成字节数 |
| WFP | 按层连接授权、流和过滤 | 所有层都有完整进程信息或TLS明文 |
| ETW | 已启用Provider发布的事件 | 任意动作都发布事件、都可同步拦截 |

### 进程回调的基本逻辑
下列是接口片段，不是可编译完整驱动；EVENT、TryPushCopy等由实现者提供。它只复制记录，不在通知回调里联网或做复杂分析。

```c
VOID OnProcess(PEPROCESS p, HANDLE pid, PPS_CREATE_NOTIFY_INFO n) {
    EVENT e = {0};
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    e.time = now.QuadPart;
    e.pid = HandleToULong(pid);
    e.start = PsGetProcessCreateTimeQuadPart(p);
    e.type = n ? CREATE_NOTIFY : EXIT_NOTIFY;
    if (n) {
        e.parent = HandleToULong(n->ParentProcessId);
        e.creator = HandleToULong(n->CreatingThreadId.UniqueProcess);
        e.creation_status = n->CreationStatus;
        if (n->CommandLine && n->CommandLine->Buffer) {
            e.available = TRUE;
            e.bytes = min(n->CommandLine->Length,
                          sizeof(e.command) - sizeof(WCHAR));
            RtlCopyMemory(e.command, n->CommandLine->Buffer, e.bytes);
            e.truncated = e.bytes < n->CommandLine->Length;
        }
    }
    TryPushCopy(&e);
}
```

e.command须为定长WCHAR数组；队列必须复制整个记录，不能保存栈地址。命令行指针只在有效生命周期内使用。缺失、空字符串、被截断不能混为一谈。[PS_CREATE_NOTIFY_INFO](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info)允许回调改变CreationStatus，因此该创建通知本身不是成功执行证明。

### 一条事件如何到达平台
假设回调得到PID640、创建时间T0、父PID200、实际创建者PID100：复制为记录 → 入有界队列 → 用户态读出 → 加入host/boot/序号 → 落盘 → 批量上传。中心保存的是这一次通知及其字段，不是补写“200亲自执行了创建”。身份区别见[进程身份](process-identity.md)。

文件写入同样需要结果：前置收到4096字节请求；后置完成状态成功且Information=2048时，报告完成2048字节。前置请求后置通知可使用FLT_PREOP_SUCCESS_WITH_CALLBACK；适用路径下结束操作则需要对应状态与FLT_PREOP_COMPLETE，不能泛化为任意接口 `return false`。[Minifilter契约](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_pre_operation_callback)。

### 事件记录与定时状态查询
[osquery 2014年发布说明](https://engineering.fb.com/2014/10/29/security/introducing-osquery/)展示了SQL状态表和定时差分。假设00秒和60秒查询进程表，一个进程10秒创建、12秒退出，两次查询都没有它；差分无法重建该过程。这不表示所有版本的osquery都没有事件能力，只限定这个轮询例子。

```sql
SELECT pid, name, path FROM processes WHERE name = 'worker';
```

2014年Sysmon v1公告列出进程创建、网络连接和文件创建时间修改；后续Event ID 11等不能倒填为第一版能力。Sysmon能提供事件，但不是完整检测与响应产品。[v1公告](https://learn.microsoft.com/en-us/archive/blogs/sysinternals/new-sysmon-v1-0-updates-autoruns-v12-01-coreinfo-v3-3-procexp-v16-03)。

## 审计
分别核实事件版本、时间源、身份字段、操作阶段、状态码、丢失计数和字段截断。回调注册/卸载、驱动签名、并发、非分页内存和设备通信均需真实WDK环境验证；本次未编译加载这些片段。

## 易错
- ETW异步消费不是通用的同步阻断点；WFP授权事件不等于连接已建立。
- 回调时间、进程创建时间、事件到达服务器时间是不同字段。
- 持续采集不等于完整录像；部署前、过滤掉和丢失的数据不能事后补造。

关联：[缓冲与丢失](telemetry-buffering.md) · [观测与检测](edr-observation-vs-detection.md) · [历史主线](README.md)
