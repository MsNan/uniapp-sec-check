# uniapp-sec-check

[![test](https://github.com/MsNan/uniapp-sec-check/actions/workflows/test.yml/badge.svg)](https://github.com/MsNan/uniapp-sec-check/actions/workflows/test.yml)
[![npx](https://img.shields.io/badge/npx-github%3AMsNan%2Funiapp--sec--check-green)](https://github.com/MsNan/uniapp-sec-check)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

**uni-app / 微信小程序上线前安全自查**：一条命令扫出「AppSecret / 支付密钥写进前端」「请求地址还是 http」「requiredPrivateInfos 没声明」「permission 缺用途说明」「pages.json / 分包配错（tabBar 写进分包、路径写成全路径、分包嵌套）」「隐私接口要去后台声明」「vConsole / setEnableDebug 没关」这类上线前最容易漏的问题。

- 离线、零依赖、只用确定性规则（正则 + JSON 解析），不联网、不上传代码、不调用 AI
- 每条规则都对应微信 / 微信支付 / DCloud 官方文档（`--rules` 查看），没有官方依据的只标为「工程卫生」
- 人看的中文报告 + `--json`，有错误时退出码 1，可直接放进 CI
- 附带 `skills/uniapp-sec-check/SKILL.md`，Claude Code / Cursor 等 agent 能按它运行并逐条修复

> English: [README.en.md](./README.en.md)

**免责声明**：与微信 / 腾讯 / DCloud 无关。规则命中少不代表能过审或绝对安全，只是把能静态判断的坑先排掉。

---

## 快速开始

```bash
# 在 uni-app 项目根目录（有 manifest.json 或 src/manifest.json）
npx -y github:MsNan/uniapp-sec-check

# 指定目录 / 输出 JSON / 警告也算失败
npx -y github:MsNan/uniapp-sec-check ./my-app --json
npx -y github:MsNan/uniapp-sec-check ./my-app --strict

# 查看全部规则和官方依据
npx -y github:MsNan/uniapp-sec-check --rules
```

输出示例（节选，来自 `test/fixtures/bad-app`，里面的密钥都是 `FAKE_...` 假数据）：

```text
✖ 错误 SEC001 前端代码里写死了 AppSecret / secret 类密钥
   config/wx.js:4
   appSecret 是写死的字符串 FAKE***（29 位）。前端/小程序包可以被解包，密钥要放到服务端；已提交过的请立即重置。
✖ 错误 MAN004 用了地理位置接口但没在 requiredPrivateInfos 声明
   pages/index/index.vue:13
   用了 getLocation（共 1 处），但 manifest.json 的 mp-weixin.requiredPrivateInfos 没有声明，2022-07-14 后发布的小程序会无法调用。
⚠ 警告 NET003 mp-weixin.setting.urlCheck 关闭了域名校验
...
合计：10 错误，10 警告，6 提示
```

| 选项 | 说明 |
| --- | --- |
| `--json` | 输出 JSON：`{ root, manifest, filesScanned, summary, findings[] }`，每条含 `id / rule / severity / file / line / message` |
| `--strict` | 有警告也返回 1 |
| `--disable ID,ID` | 关闭指定规则 |
| `--include-uni-modules` | 也扫描 `uni_modules`（默认跳过插件） |
| `--rules` | 列出规则和依据链接 |

退出码：`0` 通过；`1` 有错误（`--strict` 时含警告）；`2` 参数或目录错误。

单行忽略：在该行或上一行写注释 `sec-check-ignore`（例如页面上展示的 http 文字）。

---

## 检查什么

| ID | 级别 | 检查 | 依据 |
| --- | --- | --- | --- |
| SEC001 | 错误 | `appSecret` / `secret` / `client_secret` 等字段写死成字符串 | [微信·网络](https://developers.weixin.qq.com/miniprogram/dev/framework/ability/network.html)：AppSecret 应保存在后台服务器 |
| SEC002 | 错误 | `apiV3Key` / `mchKey` / `partnerKey` / `paySignKey` 等支付密钥写死 | [微信支付·配置 APIv3 密钥](https://pay.weixin.qq.com/doc/v3/merchant/4012072195)、[密钥泄漏修复指引](https://pay.weixin.qq.com/doc/v3/merchant/4012073693) |
| SEC003 | 错误 | 文件里出现 `-----BEGIN ... PRIVATE KEY-----` | 同上 |
| SEC004 | 错误/警告 | 工程里有 `apiclient_key.pem`、`.p12`、`.pfx`、`.key`（错误）或 `.pem/.crt/.cer`（警告） | 同上 |
| SEC005 | 错误 | `.env*` 里 SECRET / APIV3 / MCH_KEY 等变量有值（`VITE_`/`VUE_APP_` 前缀会提示「会被打包进前端」） | 同上 |
| SEC006 | 错误 | 代码里请求 `api.weixin.qq.com` | [微信·网络](https://developers.weixin.qq.com/miniprogram/dev/framework/ability/network.html)：不能配成服务器域名，相关 API 不能在小程序内调用 |
| NET001 | 错误/警告/提示 | `http://` / `ws://`：像请求地址的行（含 url/baseURL/request 等）为错误，其它公网地址为警告，本机地址警告，局域网地址提示 | [微信·网络](https://developers.weixin.qq.com/miniprogram/dev/framework/ability/network.html)：只支持 https / wss，不能用 localhost |
| NET002 | 警告 | `sslVerify: false` | [uni.request](https://uniapp.dcloud.net.cn/api/request/request.html)：关闭证书校验「不推荐」 |
| NET003 | 警告 | `mp-weixin.setting.urlCheck: false` | [uni-app manifest](https://uniapp.dcloud.net.cn/collocation/manifest.html)、微信·网络「跳过域名校验」 |
| MAN001 | 警告/错误 | 找不到 manifest.json / 解析失败（支持注释和尾逗号） | uni-app manifest |
| MAN002 | 警告 | `mp-weixin.appid` 为空 | uni-app manifest |
| MAN003 | 错误/警告 | `mp-weixin.permission` 某项缺 `desc`（错误）或超过 30 字（警告） | [微信·全局配置 permission](https://developers.weixin.qq.com/miniprogram/dev/reference/configuration/app.html) |
| MAN004 | 错误 | 用了 8 个地理位置接口之一但 `requiredPrivateInfos` 未声明 | 微信·全局配置 requiredPrivateInfos（2022-07-14 后发布的小程序） |
| MAN005 | 警告/提示 | `requiredPrivateInfos` 有不支持的值（警告）或声明了但没扫到调用（提示） | 同上 |
| MAN006 | 警告 | 用了 getLocation 等精确定位接口但没有 `scope.userLocation` 用途说明 | uni-app manifest：「申请位置权限必须填此处」 |
| MAN007 | 提示 | 还留着 `__usePrivacyCheck__`（2023-10-17 后已无作用） | [微信·隐私协议开发指南](https://developers.weixin.qq.com/miniprogram/dev/framework/user-privacy/PrivacyAuthorize.html) |
| PRV001 | 提示 | 用到隐私接口/组件（手机号、位置、相册、剪切板、麦克风、摄像头、蓝牙……），按信息类型汇总，提醒在《用户隐私保护指引》声明 | [隐私保护指引内容介绍](https://developers.weixin.qq.com/miniprogram/dev/framework/user-privacy/miniprogram-intro.html) |
| DBG001 | 警告/提示 | `console.log/debug` 计数（vite 配了 drop console 时降为提示） | 工程卫生 |
| DBG002 | 警告 | 引入 vConsole / eruda，或放在 dependencies | 工程卫生 |
| DBG003 | 错误 | `setEnableDebug({ enableDebug: true })` | [wx.setEnableDebug](https://developers.weixin.qq.com/miniprogram/dev/api/base/debug/wx.setEnableDebug.html)：对正式版也生效 |
| PAG001 | 警告/错误 | 找不到 pages.json（与 manifest 同目录）或原生 app.json（警告）；文件存在但 JSONC 解析失败（错误）。同时写了 subPackages 和 subpackages 时警告并采用 subPackages。无 manifest 且无 pages/app.json 时跳过（不与 MAN001 叠报） | [uni-app pages.json](https://uniapp.dcloud.net.cn/collocation/pages.html)、[微信·全局配置](https://developers.weixin.qq.com/miniprogram/dev/reference/configuration/app.html) |
| PAG002 | 错误 | `pages` 缺失、不是非空数组，或某项既不是非空字符串也不是带非空 `path` 的对象 | uni-app pages.json：pages 必填，第一项是首页 |
| PAG003 | 错误 | 配置了页面但找不到对应的 `.vue` / `.nvue` / `.uvue` / `.js` / `.ts` 文件（路径相对 pages.json / app.json 所在目录） | uni-app pages.json：「文件名不需要写后缀」 |
| PAG004 | 错误 | 归一化后同一完整路径在主包、某一分包、或主包与分包之间重复出现 | uni-app pages.json、[微信·分包](https://developers.weixin.qq.com/miniprogram/dev/framework/subpackages/basic.html) |
| PAG005 | 错误 | 某个分包缺少非空 `root`，或 `pages` 不是数组 | 微信·分包、uni-app pages.json |
| PAG006 | 错误 | 分包页面路径以 `/` 开头，或带上了该包自己的 `root` 前缀（例如 root 为 `pagesA` 却写成 `pagesA/list/list`） | uni-app pages.json：「subPackages 里的 pages 的路径是 root 下的相对路径，不是全路径」 |
| PAG007 | 错误 | 两个分包 `root` 相同或一个是另一个的目录前缀（`package` 与 `packageA` 不算）；或两个分包共用同一个非空 `name` | 微信·分包：「subPackages 的根目录不能是另外一个 subPackages 内的子目录」 |
| PAG008 | 错误 | `tabBar.list[].pagePath` 不在主包 `pages` 中（只在分包里也报错） | 微信·分包：「tabBar 页面必须在主包内」；uni-app pages.json：pagePath「必须在 pages 中先定义」 |
| PAG009 | 错误 | 存在 `tabBar` 但 `list` 缺失、不是数组，或数量不在 2–5 | uni-app pages.json、微信·全局配置：最少 2 个、最多 5 个 |
| PAG010 | 错误 | `preloadRule` 的 key 不是已配置的页面完整路径 | [微信·分包预下载](https://developers.weixin.qq.com/miniprogram/dev/framework/subpackages/preload.html) |
| PAG011 | 错误 | `packages` 缺失或不是数组，或其中的项不是已知分包 `root` / `name` / `__APP__` | 同上 |
| PAG012 | 错误 | `network` 存在但不是 `all` 或 `wifi` | 同上：可选 all / wifi，默认 wifi |

**扫描范围**：默认跳过 `node_modules`、`unpackage`、`dist`、`.git`、`.hbuilderx`、`uni_modules`。密钥 / 证书 / `.env` 规则扫整个项目；http、调试、隐私和定位接口这类「代码规则」只看 manifest 所在目录（`src/manifest.json` 布局就只看 `src/`），同仓库里的 `server/`、`scripts/` 不算进小程序包。

**不做的事**：不检查服务端代码逻辑、不联网核对后台域名或隐私指引是否已填、不做 App 端 Android 权限/隐私弹窗合规（这部分可用我的 [uniapp-privacy-check-web](https://github.com/MsNan/uniapp-privacy-check-web)）、不是通用 secret scanner（真实项目建议同时开 GitHub secret scanning / gitleaks）。

---

## 给 AI agent 用（SKILL.md）

把 `skills/uniapp-sec-check/` 整个目录拷到项目里：

- Claude Code：`.claude/skills/uniapp-sec-check/SKILL.md`
- Cursor：`.cursor/skills/uniapp-sec-check/SKILL.md`（Cursor 也会读 `.claude/skills/`）

```bash
mkdir -p .claude/skills && cp -r /path/to/uniapp-sec-check/skills/uniapp-sec-check .claude/skills/
```

之后对 agent 说「上线前做一次安全自查」，它会运行 `npx -y github:MsNan/uniapp-sec-check . --json`，先修错误、再处理警告，并提醒你重置已经泄露的密钥（只删代码不够）。

## 放进 CI

```yaml
- run: npx -y github:MsNan/uniapp-sec-check . --disable DBG001
```

## 开发

```bash
npm test   # node:test，零依赖；fixtures 在 test/fixtures（假密钥全部是 FAKE_ 开头）
```

```
bin/cli.js        命令行
lib/scan.js       扫描与规则实现
lib/rules.js      规则元数据与官方来源
lib/strip.js      去注释（保持行号）、JSONC 解析
lib/report.js     中文文本报告
skills/           agent 技能
test/             测试与样例项目
```

相关仓库：[uniapp-wx-lab](https://github.com/MsNan/uniapp-wx-lab)（支付 + 订阅消息联调）、[vue-uniapp-skills](https://github.com/MsNan/vue-uniapp-skills)（Vue3 + uni-app 编码技能）。

## License

MIT © Theo（涛哥）
