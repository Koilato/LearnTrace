# 2007 年系统沙箱：API 调用怎样变成行为报告（N04）

## 一句话
在带操作系统的分析环境中运行样本，通过 API 包装记录请求和结果；观察到的是本次执行路径，不是程序全部能力。

## 原理
### 当时的工程增量
CPU模拟器可以更新虚拟内存，但样本要求创建文件、注册表或网络连接时，还需要操作系统语义。[CWSandbox 作者2007年论文](https://www.researchgate.net/publication/3437907_Toward_Automated_Dynamic_Malware_Analysis_Using_CWSandbox)描述了API hooking和监视DLL；实验运行于VMware Server中的Windows XP。不要把今天的ETW/eBPF遥测倒填为它当年的实现。

```text
干净系统 → 运行样本并安装监视 → API入口转入包装函数
→ 复制参数 → 调用原函数跳板 → 保存返回结果 → 汇总报告 → 恢复环境
```

跳板保留被覆盖指令，再转回原函数未修改部分。以下只说明包装层，不提供安装钩子或DLL注入器；`real_CreateFileW`、日志缓冲和重入保护是外部设施，未编译/部署。

```c
HANDLE WINAPI observed_CreateFileW(
    LPCWSTR path, DWORD access, DWORD share,
    LPSECURITY_ATTRIBUTES sa, DWORD disposition,
    DWORD flags, HANDLE template_file)
{
    DWORD before = GetLastError();
    ULONG id = log_attempt_copy(path, access, share, disposition);
    SetLastError(before);
    HANDLE h = real_CreateFileW(path, access, share, sa,
                               disposition, flags, template_file);
    DWORD after = GetLastError();
    log_result(id, h != INVALID_HANDLE_VALUE, h, after);
    SetLastError(after);
    return h;
}
```

原函数只调用一次；日志函数要复制短生命周期参数；线程错误码不能被记录过程污染。若日志函数本身调用被钩住的API，还需每线程重入保护和不递归的缓冲路径，否则记录会引发更多记录甚至死循环。

### 输入与输出不能只看函数名称
根据[CreateFileW语义](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)，`CREATE_ALWAYS` 成功打开已有文件可以返回有效句柄，同时 last-error 为183。

| 操作 | 实际结果 | 可以报告的事实 |
|---|---|---|
| 用CREATE_ALWAYS打开已有note.txt | 有效句柄，183 | 成功打开并截断，不是失败 |
| 同步WriteFile请求写入4字节 | 成功，实际4字节 | 本次写入成功 |
| 注册表设置Run值 | 返回0 | 配置成功写入 |
| 注册表设置被拒绝 | 返回5 | 只有尝试，没有成功配置 |

注册表API直接返回状态，不能机械套用GetLastError。写入启动项也不证明下次登录已经发生。记录应同时包含操作、对象、请求参数、成功标志、实际结果和关联ID。

## 审计
先用受控正常程序验证：创建已有文件、无权限写入、部分/失败写入及正常安装行为，检查日志是否改变程序行为。论文中的两分钟执行窗口是其当次实验选择，不是通用安全边界。一个三分钟后才触发的教学程序，在两分钟记录中可能没有目标行为。

## 易错
- 操作系统是实际运行的来宾系统，不等于所有CPU指令由安全引擎自行解释。
- 未覆盖API、不同执行路径和环境条件仍会漏行为；一条API调用也不自动对应一项成功系统变化。
- 正常安装器也会写文件和启动项。沙箱报告供规则和分析员判读，不能把任何写操作都标恶意。
- 本页片段不在Python回归测试范围内；没有声称重建完整CWSandbox。

关联：[CPU模拟](cpu-emulation.md) · [HIPS](hips-stateful-policy.md) · [历史主线](README.md)
