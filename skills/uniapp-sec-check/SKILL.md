---
name: uniapp-sec-check
description: uni-app / 微信小程序上线前安全自查。用户准备提审、发版、上线，或问「有没有把密钥写进前端 / http 能不能用 / requiredPrivateInfos / 隐私接口声明」时使用：运行离线确定性检查器并按结果逐条修复。
---
# uni-app / 微信小程序上线前安全自查

## 什么时候用
- 准备上传代码、提交审核、发正式版之前
- 用户问 AppSecret / 支付密钥放哪、为什么真机请求失败、地理位置接口报未声明、隐私接口报 errno 112

## 步骤
1. 在项目根目录（有 `manifest.json` 或 `src/manifest.json`）运行：
   ```bash
   npx -y github:MsNan/uniapp-sec-check . --json
   ```
   不要加 `--include-uni-modules`，除非用户要求检查插件。
2. 解析 JSON：`summary` 是计数，`findings[]` 每项有 `id`、`severity`（error/warn/info）、`file`、`line`、`message`。
3. 先处理 `error`，再处理 `warn`，`info` 只汇报给用户，不擅自改。
4. 改完后重新运行，直到退出码为 0（或用户确认剩下的警告可接受）。

## 修复原则
- **SEC001/SEC002/SEC003/SEC004/SEC005（密钥、私钥、证书）**：把值从前端工程删掉，改为服务端接口提供能力（如登录 code 换 session、支付下单都放服务端）。**提醒用户：已经提交过 git 或发布过的密钥要到微信公众平台 / 商户平台重置**，只删代码不够。不要在回复里复述密钥原文（工具输出已打码）。
- **SEC006**：小程序端不要请求 `api.weixin.qq.com`，改由自己的服务端调用。
- **NET001**：请求地址改成已在小程序后台配置的 `https://` / `wss://` 域名；本机 / 局域网地址只放在开发环境分支里。展示用文字可在该行加注释 `sec-check-ignore`。
- **NET002**：去掉 `sslVerify: false`，建议换常见 CA 签发的证书。
- **MAN003/MAN004/MAN006**：在 `manifest.json` 的 `mp-weixin` 下补 `permission` 的 `desc`（≤30 字）和 `requiredPrivateInfos`，并提醒用户去小程序后台「开发管理-接口设置」开通对应接口。
- **PRV001**：不改代码，提醒用户在小程序后台《用户隐私保护指引》里勾选对应信息类型。
- **DBG001/DBG002/DBG003**：调试代码只在开发环境加载；console 可用构建配置移除。

## 不要做
- 不要为了让检查通过而用 `--disable` 关掉错误类规则，除非用户明确同意。
- 不要声称「检查通过 = 能过审 / 绝对安全」，这只是确定性规则自查。
- `manifest.json` 允许注释，修改时保留原有注释和格式。

规则依据：运行 `npx -y github:MsNan/uniapp-sec-check --rules` 查看每条规则对应的官方文档链接。
