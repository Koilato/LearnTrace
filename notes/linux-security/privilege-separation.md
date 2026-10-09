# Linux 权限分离与最小权限

## 一句话

**Privilege Separation = 按职责拆分进程/组件，将特权操作限制在最小可信代码范围内；Least Privilege = 每个主体只获得完成任务所需的权限。**

## 原理

```text
高权限小组件（执行受控特权操作）
           ↑ 受限 IPC / 请求接口
低权限 Worker（处理不可信输入）
```

权限分离降低的是**单个组件被攻破后的可执行能力和横向影响**，不是保证组件不会被攻破。

| 控制 | 内核机制 | 解决的问题 |
|---|---|---|
| DAC | Unix rwx、ACL | 该 UID/GID 能否访问文件 |
| Capabilities | 分解传统 root 特权 | 是否必须授予全部 root 权限 |
| seccomp-BPF | 过滤系统调用（及参数） | 进程能尝试哪些 syscall |
| Namespaces | 独立资源命名/查找上下文 | 进程能看到、命名、操作哪些资源 |
| cgroups | CPU/内存等资源控制 | 能消耗多少资源 |
| LSM (SELinux/AppArmor) | 强制访问控制策略 | 即使 DAC 允许，策略是否允许 |

```text
攻击面 → 组件隔离 → 限制凭据/系统调用/资源视图 → 缩小攻陷后的影响范围
```

## 审计

- 看进程实际 UID/GID、有效/许可/边界 Capabilities：`id`、`getpcaps <pid>`、`/proc/<pid>/status`。
- 看文件权限及 ACL：`namei -l <path>`、`getfacl <path>`。
- 看 seccomp：`grep Seccomp /proc/<pid>/status`（只能确定启用状态，不能还原完整过滤规则）。
- 看资源与隔离：`lsns`、`readlink /proc/<pid>/ns/*`、`cat /proc/<pid>/cgroup`。
- 看 IPC 边界：低权限进程能否诱导高权限组件执行任意路径操作或危险系统调用。

## 易错

- **DAC ≠ 最小权限 ≠ Namespace**：分别偏向对象访问权限、主体能力约束、资源作用域。
- **seccomp ≠ syscall 完全禁用**：由配置决定允许、拒绝或其他动作；参数规则也有限制。
- **Namespace ≠ 安全沙箱**：共享内核，通常还需 LSM、Capabilities、seccomp 等防御层。
- **root in userns ≠ host root**：权限按 User Namespace 和能力作用域判断，不能凭容器内 UID=0 推断宿主权限。
