# Hypervisor、vCPU 与容器

## 一句话

**Hypervisor 提供虚拟硬件与 vCPU 状态抽象，并将 vCPU 调度到物理逻辑 CPU；容器通常直接共享 Host Kernel，通过内核机制隔离进程。**

## 原理

```text
VM:  App → Guest OS / Guest Kernel → 虚拟硬件 → Hypervisor → 物理硬件
Container: App + 用户态依赖 → Host Kernel → 物理硬件
```

以上是**逻辑结构**，不是每次系统调用都依次经过所有层：Guest 内普通 syscall 在 Guest Kernel 处理，部分硬件操作才涉及 VM exit、Hypervisor 或设备虚拟化。

| 维度 | 虚拟机 | 容器 |
|---|---|---|
| 内核 | 每个 VM 有独立 Guest Kernel | 共享宿主内核 |
| CPU | Guest 可见 vCPU，Hypervisor 调度到 pCPU | 普通宿主进程直接参与 Host CPU 调度 |
| 隔离边界 | 虚拟硬件/地址空间/Guest OS | Host Kernel 中的 Namespace、cgroups、LSM 等 |
| 管理 | Hypervisor + 管理组件 | containerd、runc 等 Runtime / 管理组件 |
| 开销 | 通常较高 | 通常较低 |

**vCPU 不等于 CPU 指令集模拟**：同架构、硬件辅助虚拟化中，大多数 Guest 指令直接在物理 CPU 上执行；跨 ISA 模拟（如软件翻译）是另一机制。

```text
Guest 所见 vCPU → Hypervisor 维护 CPU 状态 → 调度到物理逻辑 CPU
```

**管理平面 ≠ 执行路径**：容器创建需要 runtime，但 runc 一类工具可以在创建后退出，容器进程仍存活；VM 管理组件也不意味着每个 Guest syscall 都进入管理器。

## 审计

- 确定资产运行于裸机、VM 或容器，检查宿主与 Guest 内核边界。
- VM：核查虚拟设备暴露、宿主 Hypervisor 更新与管理接口权限。
- 容器：核查 privileged、宿主目录/Socket 挂载、User Namespace、Capabilities、seccomp、LSM 配置。
- 别把“有容器管理器”当作“额外独立 Guest Kernel”。

## 易错

- **Type 1 / Type 2** 是部署架构分类；实际设备访问及系统调用路径因实现而异。
- **vCPU 数可超配**物理核心数：多 vCPU 分时共享物理逻辑处理器，不能创造额外物理算力。
- **容器少的是 Guest Kernel/虚拟硬件层**，不是必然少一个“管理器”。
