# Linux Namespace：内核查找与隔离语义

## 一句话

**Namespace = 为部分内核资源定义独立的命名、查找及管理作用域；不是 syscall 结束后统一过滤结果，也不是复制完整内核。**

## 原理：先理解 Lookup 与 Authorization

```math
o = \operatorname{Lookup}(N,k),\qquad
\operatorname{Allow}(C,o,a)\in\{0,1\}
```

- `N`：资源查找作用域；`k`：PID/端口/路径等查找键；`o`：内核对象。
- `C`：凭据与安全上下文；`a`：操作。
- **能定位到对象不意味着有权操作对象**；查找与授权是两个问题。

```text
系统调用 → 确定查找上下文 → 定位内核对象 → 权限判断 → 执行操作
```

### 1. 上下文是如何附着在进程上的？

```text
current (task_struct)
├── nsproxy ──> mnt_ns / uts_ns / ipc_ns / net_ns / cgroup_ns / ...
│               └── pid_ns_for_children（决定子进程创建时的 PID NS）
├── cred ─────> user_ns + UID/GID + Capabilities
├── fs ───────> root / pwd（路径解析输入）
└── thread_pid -> struct pid（含各层级 PID 编号）
```

此图为简化关系：某些 Namespace 另有线程相关字段；**当前任务的 active PID Namespace 不等于 `pid_ns_for_children`**；不能假设所有资源操作都直接读取 `current->nsproxy`。

### 2. PID Namespace：局部整数如何映射到内核对象？

一个进程在不同祖先层级中可以有不同 PID：

```text
struct pid
  numbers[0] = {nr: 4201, ns: host}
  numbers[1] = {nr: 1,    ns: container_A}
```

`numbers[]` 中的元素对应 `struct upid`，包含编号 `nr` 与对应的 `pid_namespace`。

典型 PID 查找思想：

```c
// 伪代码：忽略 RCU/引用计数/边界条件
struct pid *find_pid_ns(int nr, struct pid_namespace *ns) {
    return idr_find(&ns->idr, nr);
}
```

在同一内核里，`(namespace A, PID 1)` 和 `(namespace B, PID 1)` 可以解析到不同 `struct pid`，因为查找在对应 Namespace 的索引中进行。Host/祖先 Namespace 可为后代进程维护编号；子 Namespace 不会因此获得祖先进程的全局 PID 视图。发送信号时还须单独通过权限检查。

### 3. Network Namespace：为何两个容器都能绑定 TCP :80？

Socket 的网络命名空间由 Socket 自身的关联上下文决定；内核常通过 `sock_net(sk)` 获取，不必每次用当前任务的 `net_ns`。

```text
socket(sk) → sock_net(sk) → struct net
                              ├── 网络设备/路由状态
                              └── TCP bind 与冲突检查作用域
```

不同 `struct net` 的 TCP 端口空间相互隔离，因此相同地址与端口可以在不同 Network Namespace 中分别绑定（仍受各自地址、权限、冲突规则约束）。已创建的 Socket 不会因进程后来切换 Network Namespace 就自动迁移。

### 4. 不同 Namespace 的查找方式并不统一

| 类型 | 隔离重点 | 查找/解释上下文 |
|---|---|---|
| PID | 进程编号与可见性 | `pid_namespace` + 局部 PID 索引、祖先层级映射 |
| Network | 设备、路由、协议状态、端口 | `struct net` + 子系统索引 |
| Mount | 挂载拓扑 | 路径解析上下文、`mount namespace`、mount/dentry |
| UTS | 主机名、域名 | 独立 Namespace 字段 |
| IPC | SysV IPC / POSIX 消息队列 | 对应 IPC 命名空间的对象索引 |
| User | UID/GID 映射、能力作用域 | `cred->user_ns`、ID 映射与权限检查 |
| Cgroup | cgroup 路径视图 | 相对 cgroup root 的可见路径 |
| Time | 部分时钟偏移 | 时间命名空间偏移（如 monotonic/boottime） |

**Mount 特别注意**：路径解析涉及 `fs_struct`（root/pwd）、挂载树、dentry、VFS lookup，不等于“为每个 Namespace 复制一套文件内容”。

### 5. 创建和加入 Namespace

| 接口 | 意义 |
|---|---|
| `clone()/clone3()` | 创建任务时可请求新 Namespace |
| `unshare()` | 对部分共享上下文解除共享并创建新 Namespace |
| `setns()` | 加入已有 Namespace（受权限和类型限制） |

```bash
sudo unshare --pid --fork --mount-proc bash
echo $$
ps -ef
lsns
readlink /proc/self/ns/pid
```

新 Bash 一般在新 PID Namespace 中为 PID 1；`--fork` 必要，因为新的 PID Namespace 对随后创建的子任务生效。与 `/proc` 的挂载视图一起理解，否则 `ps` 结果可能误导。

## 安全审计

- **枚举**：`lsns`，`readlink /proc/<pid>/ns/{pid,net,mnt,user}`；核查是否与宿主共享预期之外的 Namespace。
- **PID**：检查可见 PID 与祖先 PID Namespace，确认进程目标解析语义，不以“能看见”替代授权检查。
- **Network**：`ip netns exec <name> ip addr`、`ss -lnt`；同端口跨 Namespace 不意味着同网络可达。
- **Mount**：`findmnt`、`/proc/<pid>/mountinfo`；重点核查宿主敏感路径及 Socket 是否被 bind mount 到容器。
- **User/Capabilities**：`/proc/<pid>/uid_map`、`gid_map`、`status`；核查 ID 映射与有效特权边界。
- **复现**：优先在测试环境运行 `unshare`，不同发行版可能禁用无特权 User Namespace。

## 易错

- **Namespace 并非统一的“过滤器”**：各子系统分别实现其资源查找作用域。
- **当前任务 Namespace ≠ 对象 Namespace**：Socket、PID 等对象可携带自己的归属信息。
- **Namespace ≠ 授权**：`kill()` 找到 PID 后仍做信号权限检查。
- **Namespace ≠ cgroups**：前者隔离资源视图，后者主要控制用量；Cgroup Namespace 仅隔离路径视图。
- **Namespace ≠ 强内核边界**：容器之间共享内核，需结合 Capabilities、seccomp、LSM 与宿主加固。
- **传统 Unix `chroot`、UID/GID ≠ Linux Namespace**；FreeBSD Jail、Solaris Zones 目标类似但实现不同。

## 继续深入的源码入口

- `include/linux/nsproxy.h`、`kernel/nsproxy.c`：Namespace 引用与切换。
- `include/linux/pid.h`、`kernel/pid.c`：`struct pid`、`find_pid_ns`、PID 分配/查找。
- `include/net/net_namespace.h`、`net/core/net_namespace.c`：网络命名空间生命期。
- `fs/namei.c`、`fs/namespace.c`：VFS 路径解析与挂载树。
- `kernel/user_namespace.c`、`kernel/cred.c`：User Namespace 与凭据。

> 源码字段/调用链会随内核版本变化，应以目标内核版本为准；本文中的代码结构均为简化模型。
