# uniapp-sec-check

[![test](https://github.com/MsNan/uniapp-sec-check/actions/workflows/test.yml/badge.svg)](https://github.com/MsNan/uniapp-sec-check/actions/workflows/test.yml)

**Pre-launch security self-check for uni-app / WeChat mini-program projects.** One command finds the things that usually slip through before release: AppSecret or WeChat Pay keys hardcoded in the client, `http://` request URLs, missing `requiredPrivateInfos`, `permission` entries without `desc`, broken `pages.json` / subpackage config (tabBar page in a subpackage, non-relative subpackage paths, nested roots), privacy APIs that must be declared in the privacy guide, and leftover vConsole / `setEnableDebug`.

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
| PAG001 | Missing `pages.json` (next to the manifest) or native `app.json` (warning); JSONC parse failure (error). If both `subPackages` and `subpackages` exist, warn and use `subPackages`. Skip entirely when there is no manifest and no pages/app.json |
| PAG002 | `pages` missing, not a non-empty array, or an entry that is neither a non-empty string nor an object with a non-empty `path` |
| PAG003 | A configured page has no matching `.vue` / `.nvue` / `.uvue` / `.js` / `.ts` file (resolved relative to the config file’s directory) |
| PAG004 | The same normalized full path appears twice (in main pages, in one subpackage, or across main + subpackages) |
| PAG005 | A subpackage is missing a non-empty `root`, or `pages` is not an array |
| PAG006 | A subpackage page path is absolute (`/…`) or prefixed with that package’s own `root` (it must be a path relative to `root`, not a full path) |
| PAG007 | Two subpackage roots are equal or one is a directory prefix of the other (`package` vs `packageA` is fine); or two subpackages share the same non-empty `name` |
| PAG008 | A `tabBar.list[].pagePath` is not in the main package `pages` (still an error if it only appears in a subpackage; tabBar pages must live in the main package) |
| PAG009 | `tabBar` exists but `list` is missing, not an array, or its length is not in 2–5 |
| PAG010 | A `preloadRule` key is not a configured page full path |
| PAG011 | `packages` is missing or not an array, or an item is not a known subpackage `root`, `name`, or `__APP__` |
| PAG012 | `network` is present and is not `all` or `wifi` |

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
