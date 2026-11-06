# 浏览器指纹（Browser Fingerprinting）

## 一句话
**浏览器指纹**是网站通过 HTTP/TLS、JavaScript API、渲染结果和会话行为采集客户端特征，并据此做环境识别、异常检测或风险评估的一组技术；它是**概率性特征组合**，不等于稳定、唯一的设备 ID。

## 原理
**采集信号 → 标准化 → 跨层一致性检查 → 风险判断**。字段应区分“浏览器主动报告的属性”“环境运行结果”“服务端观察值”；下表均为**真实可能出现的取值或合法格式示例**，并非采集自同一设备。

### L1–L2：HTTP 与 Client Hints

| 指标 | 全称 | 具体作用 | 真实的值示例 |
|---|---|---|---|
| `User-Agent` | User Agent | HTTP 请求头中的浏览器、系统身份声明 | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36` |
| `Accept` | Accept | 声明可接受的 MIME 类型 | `text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` |
| `Accept-Language` | Accept Language | 声明内容语言偏好 | `zh-CN,zh;q=0.9,en;q=0.8` |
| `Accept-Encoding` | Accept Encoding | 声明支持的响应压缩编码 | `gzip, deflate, br, zstd` |
| `Referer` | Referer（历史拼写） | 传递来源页面 URL，受 Referrer-Policy 约束 | `https://example.org/docs/42` |
| `Sec-CH-UA` | User-Agent Client Hint | 浏览器品牌及主版本；可能包含 GREASE 品牌 | `"Chromium";v="120", "Google Chrome";v="120"`（片段） |
| `Sec-CH-UA-Mobile` | User-Agent Mobile Client Hint | 报告是否为移动端上下文 | `?0`（非移动端） |
| `Sec-CH-UA-Platform` | User-Agent Platform Client Hint | 报告操作系统平台 | `"Windows"` |
| `Sec-CH-UA-Full-Version-List` | User-Agent Full Version List Client Hint | 提供浏览器品牌的完整版本列表（高熵提示） | `"Chromium";v="120.0.6099.109", "Google Chrome";v="120.0.6099.109"`（示例片段） |

注：`Sec-` 是保留的请求头前缀，`CH` = Client Hints，`UA` = User Agent；不是所有 Client Hints 每次都会发送，高熵提示可能依赖 `Accept-CH`、浏览器策略和安全上下文。

### L3–L6：Navigator、硬件、屏幕、区域

| 指标 | 全称 | 具体作用 | 真实的值示例 |
|---|---|---|---|
| `navigator.userAgent` | Navigator User Agent | JS 可读的 UA 字符串，可和 HTTP UA 比对 | `"Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."`（截断） |
| `navigator.platform` | Navigator Platform | 浏览器报告的平台名称，不保证反映真实系统 | `"Win32"` |
| `navigator.language` | Navigator Language | 浏览器首选语言 | `"zh-CN"` |
| `navigator.languages` | Navigator Languages | 浏览器偏好语言列表 | `["zh-CN","zh","en-US"]` |
| `navigator.vendor` | Navigator Vendor | 浏览器供应商标识 | `"Google Inc."` |
| `navigator.hardwareConcurrency` | Hardware Concurrency | 浏览器可用逻辑处理器数量（可能被限制） | `8` |
| `navigator.deviceMemory` | Device Memory | 浏览器报告的近似内存档位，单位 GiB；部分浏览器不支持 | `8` |
| `navigator.maxTouchPoints` | Maximum Touch Points | 支持的最大同时触控点数 | `0`、`5` |
| `screen.width` | Screen Width | 屏幕宽度（CSS 像素） | `1920` |
| `screen.height` | Screen Height | 屏幕高度（CSS 像素） | `1080` |
| `screen.availWidth` | Available Screen Width | 屏幕可用宽度 | `1920` |
| `screen.availHeight` | Available Screen Height | 屏幕可用高度，可能扣除系统界面 | `1040` |
| `screen.colorDepth` | Screen Color Depth | 颜色位深信息 | `24` |
| `window.devicePixelRatio` | Device Pixel Ratio（DPR） | 物理像素与 CSS 像素的比例 | `1`、`2` |
| `window.innerWidth` | Window Inner Width | 当前网页视口宽度 | `1280` |
| `window.innerHeight` | Window Inner Height | 当前网页视口高度 | `900` |
| `Intl.DateTimeFormat().resolvedOptions().timeZone` | Internationalization Date-Time Format Time Zone | 系统/浏览器当前时区标识 | `"Asia/Shanghai"` |
| `Date.getTimezoneOffset()` | Date Time Zone Offset | UTC 与本地时间差（分钟，随夏令时可能改变） | `-480`（UTC+8） |

注：屏幕尺寸 ≠ 浏览器视口尺寸；`navigator.deviceMemory` 是近似值；时间偏移的正负号容易与 UTC± 的习惯表示混淆。

### L7–L9：图形、音频和功能能力

| 指标 | 全称 | 具体作用 | 真实的值示例 |
|---|---|---|---|
| Canvas | HTML Canvas API | 同一绘图内容的像素差异可能反映字体、引擎和图形环境 | `data:image/png;base64,iVBORw0KGgo...`（图像数据前缀，不是指纹哈希） |
| WebGL | Web Graphics Library | 浏览器 3D 图形 API 及版本 | `WebGL 2.0` |
| `WebGL VENDOR` | WebGL Vendor | 浏览器 WebGL 实现报告的厂商，可能被掩码 | `"WebKit"` |
| `WebGL RENDERER` | WebGL Renderer | 渲染器标识，可能为掩码值 | `"WebKit WebGL"` |
| WebGL extensions | WebGL Extensions | 支持的 GPU/渲染扩展集合 | `["OES_texture_float","WEBGL_debug_renderer_info"]` |
| `AudioContext` | Web Audio AudioContext | 实时音频处理；采样率和处理输出可作环境信号 | `sampleRate: 48000` |
| `OfflineAudioContext` | Web Audio OfflineAudioContext | 离线音频渲染的数值输出可能存在实现差异 | `sampleRate: 44100, length: 44100` |
| `navigator.plugins` | Navigator Plugins | 查询浏览器暴露的插件；现代浏览器可能统一或限制 | `["PDF Viewer","Chrome PDF Viewer"]` |
| `navigator.permissions` | Permissions API | 查询特定权限状态（需指定权限名） | `"prompt"`、`"granted"`、`"denied"` |
| `navigator.mediaDevices` | Media Devices API | 访问音视频设备接口，枚举结果受授权和隐私策略影响 | `{kind:"audioinput",deviceId:"[已脱敏]"}` |
| Fonts | Font Availability / Font Fingerprinting | 通过字体及文本度量差异观察系统环境 | `"Arial"`、`"Microsoft YaHei"` |
| WebRTC | Web Real-Time Communication | 实时通信能力；ICE 候选、编解码器等可反映环境 | ICE 候选类型：`host`、`srflx`、`relay` |

注：WebGL 掩码厂商/渲染器与通过可用扩展查询到的详细值不同；Canvas 与音频的“指纹”通常需要**固定测试输入 + 输出处理/哈希**，不能只把 API 名称当作指纹值。

### L10–L12：TLS/HTTP2、自动化、会话与行为

| 指标 | 全称 | 具体作用 | 真实的值示例 |
|---|---|---|---|
| TLS | Transport Layer Security | 加密传输协议；其握手特征可用于客户端归类 | `TLS 1.3` |
| ClientHello | TLS ClientHello Message | TLS 握手消息，携带密码套件、扩展和版本等 | `supported_versions=0x0304`、`cipher_suite=0x1301` |
| JA3 | JA3 TLS Fingerprinting（算法名） | 基于 ClientHello 选定字段计算 MD5 客户端指纹 | `e7d705a3286e19ea42f587b344ee6865`（公开示例） |
| JA4 | JA4 TLS Fingerprinting（算法名） | 使用更规范化的 TLS/协议特征归类客户端 | `t13d1516h2_8daaf6152771_e5627efa2ab1`（公开示例） |
| ALPN | Application-Layer Protocol Negotiation | TLS 握手时协商应用层协议 | `["h2","http/1.1"]` |
| HTTP/2 SETTINGS | Hypertext Transfer Protocol Version 2 Settings | 配置头部表、流控窗口、并发等连接属性 | `SETTINGS_INITIAL_WINDOW_SIZE=65535` |
| `navigator.webdriver` | Navigator WebDriver | 表明浏览器是否报告 WebDriver 自动化控制 | `true`、`false` |
| Browser Environment | Browser Runtime Environment | JS API、功能及运行差异的组合观察（非单个字段） | `typeof WebGLRenderingContext === "function"` → `true` |
| Cookies | HTTP Cookies | 保存/携带会话状态，具体值须脱敏 | `sessionid=[已脱敏]` |
| LocalStorage | Web Storage Local Storage | 同源持久化键值数据，不自动随 HTTP 请求发送 | `{"theme":"dark","language":"zh-CN"}` |
| IndexedDB | Indexed Database API | 同源结构化本地数据库 | `{name:"app-cache",version:1}` |
| Request Interval | Request Time Interval | 相邻请求间隔，属于观测指标而非浏览器 API | `1200 ms` |
| Request Concurrency | Concurrent HTTP Requests | 同时进行的请求数，属于观测指标 | `6` |
| Navigation Sequence | Page Navigation Sequence | 页面访问/交互事件顺序 | `/home → /search → /view/123` |

注：表中 JA3 和 JA4 样例**不是同一会话的配套值**；Cookies 和设备 ID 应在笔记或日志中脱敏。网络层字段一般由协议栈产生，不能仅靠页面 JS 设定。

## 审计：如何判断与验证
1. **请求侧**：在浏览器开发者工具 Network/HAR 采集 `User-Agent`、Client Hints、`Accept-Language`、状态码；在自有服务端或授权网络观测点记录 TLS/HTTP2 特征。
2. **JS 侧**：在相同会话记录 `navigator`、`screen`、时区及图形能力；注意权限状态、浏览器版本、隐私设置对结果的影响。
3. **跨层核对**：比较 `User-Agent` 与 `navigator.userAgent`、平台 Client Hint 与 `navigator.platform`、语言头与 `navigator.languages`、系统时区与时间偏移；不一致是线索，**不是自动化行为的充分证明**。
4. **响应分类**：将 HTTP 403/429、验证码、登录失效、资源权限和前端渲染失败分开记录；不要统一解释为“指纹被识别”。
5. **可复现性**：保存浏览器版本、系统、测试时间、样本数量与授权测试范围；分别说明静态检查、离线测试、真实站点验证。

只读浏览器控制台采样（不包含 Cookie、设备 ID 等敏感值）：

```js
console.table({
  userAgent: navigator.userAgent,
  platform: navigator.platform,
  language: navigator.language,
  languages: navigator.languages.join(","),
  cpuThreads: navigator.hardwareConcurrency,
  approxMemoryGiB: navigator.deviceMemory ?? "unsupported",
  touchPoints: navigator.maxTouchPoints,
  screen: `${screen.width}x${screen.height}`,
  viewport: `${innerWidth}x${innerHeight}`,
  dpr: devicePixelRatio,
  timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  offsetMin: new Date().getTimezoneOffset(),
  webdriver: navigator.webdriver
});
```

## 易错
- **改 UA ≠ 模拟完整浏览器**：JS、图形、TLS 与行为未必一致。
- **指纹 ≠ 唯一设备 ID**：值会受到浏览器更新、GPU 驱动、隐私保护及共享环境影响。
- **真实值示例 ≠ 同机观测**：不能将各行拼成“真实浏览器画像”。
- **单项异常 ≠ 已触发风控**：应结合响应证据与对照实验。
- **`navigator.webdriver` ≠ 验证码开关**：它仅是可观察的自动化提示。
- **有指纹 ≠ 有权限**：页面预览、登录、下载和付费授权属于不同控制层。

## 参考
- [MDN — User-Agent Client Hints](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Client_hints)
- [MDN — Navigator](https://developer.mozilla.org/en-US/docs/Web/API/Navigator)
- [MDN — WebGL](https://developer.mozilla.org/en-US/docs/Web/API/WebGL_API)
- [MDN — Web Audio API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Audio_API)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9113 — HTTP/2](https://www.rfc-editor.org/rfc/rfc9113)
- [Salesforce — JA3](https://github.com/salesforce/ja3)
