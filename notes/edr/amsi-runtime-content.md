# AMSI：由脚本宿主提供运行时内容（N13）

## 一句话
AMSI把“在哪里取得脚本内容”和“如何判断内容”分开：宿主在实际解释路径送检，反恶意引擎判定，宿主依据结果执行策略。

## 原理
[微软2015年说明](https://www.microsoft.com/en-us/msrc/blog/2015/06/advances-in-scripting-security-and-protection-in-windows-10-and-powershell-v5)解释了Windows 10 AMSI的动机：文件扫描难还原任意脚本混淆，宿主已经需要处理这些内容，可主动请求检查。PowerShell V5的脚本块日志是相关但不同的记录机制，不应把AMSI直接等同事件日志。

```text
磁盘/输入文本 → 解释器解析或生成脚本块 → 宿主送检
→ 安全引擎返回结果 → 宿主策略 → 执行或拒绝
```

无害样例：

```powershell
$b64 = 'VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAEUARABSAF8ARABFAE0ATwBfAE0AQQBSAEsARQBSACcA'
$text = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))
Write-Output $text
```

输出是 `Write-Output 'EDR_DEMO_MARKER'`。这里仅打印解码文本；不需要Invoke-Expression就能核对编码。实际宿主要执行动态脚本时，后续形成的脚本块才可能在对应送检点被观察。**解码字符串本身不保证已经调用AMSI**，检查范围取决于宿主集成和调用位置。

宿主集成的接口骨架如下，必须区分调用失败与检测结果，不能把失败当作允许。这个片段未在Windows构建运行：

```c
HAMSICONTEXT ctx;
HRESULT hr = AmsiInitialize(L"TeachingHost", &ctx);
if (FAILED(hr)) return SCAN_UNAVAILABLE;
AMSI_RESULT result;
hr = AmsiScanBuffer(ctx, text, byte_length, L"script", NULL, &result);
AmsiUninitialize(ctx);
if (FAILED(hr)) return SCAN_UNAVAILABLE;
if (AmsiResultIsMalware(result)) return BLOCK;
return ApplyHostPolicy(result);
```

`HRESULT`检查接口执行；`AMSI_RESULT`保留扫描结论。`ApplyHostPolicy`是需要实现的宿主逻辑，包含管理员策略阻断，不能写成“不是MALWARE就放行”。参见[AmsiScanBuffer](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer)与[结果枚举](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)。

## 审计
教学扫描器若人工配置匹配标记：只拿到Base64时没有明文标记；收到解码脚本时能命中。这验证可见性差异，不代表实际安全产品会拦截无害标记。分别记录宿主送检是否发生、调用是否成功、检测结果及最后执行决定。

## 易错
- AMSI不是通用CPU/内存监视器，不会自动获得未集成宿主的所有内容。
- 运行时内容来源仍可配合特征码、启发式和模型，没有淘汰旧检测算法。
- 这些接口属于2015年之后的案例，不应作为2007年CWSandbox实现。

关联：[CPU模拟](cpu-emulation.md) · [沙箱](sandbox-api-monitoring.md) · [观测与检测](edr-observation-vs-detection.md) · [历史主线](README.md)
