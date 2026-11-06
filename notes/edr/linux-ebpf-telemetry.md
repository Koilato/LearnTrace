# Linux eBPF：从内核事件到用户态记录（N20）

## 一句话
eBPF让受验证程序在指定内核挂载点提取事件；它改善采集机制，不会自动判断恶意，也不是所有挂载点都可阻断。

## 原理
[实现者2020年说明](https://nakryiko.com/posts/bpf-ringbuf/)指出，Linux 5.8增加共享ring buffer；更早的常见传输方式是每CPU perf buffer。不能把ringbuf接口写进所有早期eBPF案例。

```text
编译并加载程序 → verifier检查 → 挂载tracepoint
→ 内核事件触发 → reserve记录 → 提取字段 → submit → 用户态消费
```

下面是Linux 5.8+与相应libbpf头文件条件下的接口片段，缺少加载器和用户态消费者，本次未编译/加载：

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct event { unsigned int tgid; char comm[16]; };
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tp/sched/sched_process_exec")
int on_exec(void *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
```

例如任务成功exec为/bin/sh，触发挂载点，产生 `{tgid:4201, comm:"sh"}`，用户态轮询取出。`comm`只有有限名称，不是完整路径/参数；字段名tgid刻意避免把线程ID与进程组ID混用。

**exec是替换进程映像，不等同创建新PID。**构建Linux生命周期时还需要fork/clone/exit等事件、启动时间及exec前后关系；不能把每条exec都当成新的Windows式进程创建实例。

## 审计
reserve失败会丢记录，需要单独计数；消费延迟、内核版本、权限、挂载点可用性与容器命名空间归属都要核对。共享ring buffer改善跨CPU传输，不等于全系统无丢失或获得所有行为因果顺序。

## 易错
- tracepoint程序返回0不表示允许/拒绝目标exec；它是在观察。
- 同步访问控制需要对应决策hook，例如[Linux 5.7的BPF LSM](https://www.kernel.org/doc/html/v5.7/bpf/bpf_lsm.html)，语义随hook而异。
- verifier检查可接受性，不代表业务策略正确、字段完整或没有性能成本。
- Python实验通过不能证明这段内核代码已通过verifier或在目标发行版工作。

关联：[缓冲与丢失](telemetry-buffering.md) · [进程身份](process-identity.md) · [历史主线](README.md)
