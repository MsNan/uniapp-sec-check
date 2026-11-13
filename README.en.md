# uniapp-sec-check

[![test](https://github.com/MsNan/uniapp-sec-check/actions/workflows/test.yml/badge.svg)](https://github.com/MsNan/uniapp-sec-check/actions/workflows/test.yml)

**Pre-launch security self-check for uni-app / WeChat mini-program projects.** One command finds the things that usually slip through before release: AppSecret or WeChat Pay keys hardcoded in the client, `http://` request URLs, missing `requiredPrivateInfos`, `permission` entries without `desc`, privacy APIs that must be declared in the privacy guide, and leftover vConsole / `setEnableDebug`.

- Offline, zero dependencies, deterministic rules only (regex + JSON parsing). No network, no upload, no AI.
- Every rule links to official WeChat / WeChat Pay / DCloud docs (`--rules`); rules without an official basis are marked as hygiene.
- Chinese human-readable report or `--json`; exit code 1 on errors, CI-friendly.
- Ships `skills/uniapp-sec-check/SKILL.md` so Claude Code / Cursor agents can run it and fix findings.

Chinese docs (primary): [README.md](./README.md)

Not affiliated with WeChat / Tencent / DCloud. Passing this check does not mean your app will pass review or is secure.

## Usage

```bash
npx -y github:MsNan/uniapp-sec-check            # current dir (manifest.json or src/manifest.json)
npx -y github:MsNan/uniapp-sec-check ./app --json
npx -y github:MsNan/uniapp-sec-check ./app --strict   # warnings also fail
npx -y github:MsNan/uniapp-sec-check --rules           # rules + sources
```

Options: `--json`, `--strict`, `--disable ID,ID`, `--include-uni-modules`, `--rules`, `-h`.
Exit codes: `0` ok, `1` errors (or warnings with `--strict`), `2` bad arguments / directory.
Suppress a single line with a `sec-check-ignore` comment on that line or the line above.

## Rules

| ID | Check |
| --- | --- |
| SEC001 | `appSecret` / `secret` / `client_secret`… assigned a string literal |
| SEC002 | WeChat Pay keys (`apiV3Key`, `mchKey`, `partnerKey`, `paySignKey`…) hardcoded |
| SEC003 | PEM `PRIVATE KEY` block in any file |
| SEC004 | Certificate / key files (`apiclient_key.pem`, `.p12`, `.pfx`, `.key`; `.pem/.crt/.cer` as warning) |
| SEC005 | Secret-like variables with values in `.env*` (notes that `VITE_` / `VUE_APP_` vars are bundled) |
| SEC006 | Client code calling `api.weixin.qq.com` |
| NET001 | `http://` / `ws://` URLs (error on request-like lines, warning otherwise, loopback warning, LAN info) |
| NET002 | `sslVerify: false` |
| NET003 | `mp-weixin.setting.urlCheck: false` |
| MAN001–MAN007 | manifest.json: missing/invalid (JSONC supported), empty `mp-weixin.appid`, `permission.desc` missing or > 30 chars, location APIs vs `requiredPrivateInfos`, missing `scope.userLocation`, obsolete `__usePrivacyCheck__` |
| PRV001 | Privacy APIs/components used (phone number, location, album, clipboard, mic, camera, Bluetooth…), grouped by info type, reminder to declare them in the privacy guide |
| DBG001–DBG003 | `console.log` count, vConsole / eruda, `setEnableDebug({ enableDebug: true })` |

Secret / cert / `.env` rules scan the whole project; code rules only scan the directory containing `manifest.json` (e.g. `src/`). `node_modules`, `unpackage`, `dist`, `.git`, `.hbuilderx`, `uni_modules` are skipped by default.

Out of scope: server-side logic, online checks of configured domains / privacy guide, App-side Android permission compliance (see [uniapp-privacy-check-web](https://github.com/MsNan/uniapp-privacy-check-web)), general-purpose secret scanning.

## Agent skill

Copy `skills/uniapp-sec-check/` to `.claude/skills/` (Claude Code) or `.cursor/skills/` (Cursor; Cursor also reads `.claude/skills/`).

## Development

```bash
npm test   # node:test, zero deps; fixtures in test/fixtures use obviously fake FAKE_ values
```

## License

MIT © Theo（涛哥）
