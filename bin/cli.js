#!/usr/bin/env node
'use strict';

const fs = require('fs');
const { scan } = require('../lib/scan');
const { formatText, formatRules } = require('../lib/report');
const { RULES } = require('../lib/rules');

const HELP = `uniapp-sec-check — uni-app / 微信小程序上线前安全自查（离线、确定性规则）

用法:
  npx -y github:MsNan/uniapp-sec-check [项目目录] [选项]

选项:
  --json                  输出 JSON（给 CI / AI agent 用）
  --strict                有警告也返回退出码 1（默认只有错误才返回 1）
  --disable <ID,ID>       关闭指定规则，如 --disable DBG001,NET001
  --include-uni-modules   也扫描 uni_modules（默认跳过）
  --rules                 列出全部规则和官方依据链接
  -h, --help              显示帮助

退出码: 0 通过；1 有错误（--strict 时含警告）；2 参数或目录错误
`;

class CliError extends Error {}

function parseArgs(argv) {
  const o = { dir: '.', json: false, strict: false, disable: [], includeUniModules: false, rules: false, help: false };
  let dirSet = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') o.json = true;
    else if (a === '--strict') o.strict = true;
    else if (a === '--include-uni-modules') o.includeUniModules = true;
    else if (a === '--rules') o.rules = true;
    else if (a === '-h' || a === '--help') o.help = true;
    else if (a === '--disable') {
      const v = argv[++i];
      if (v === undefined || v.startsWith('-')) throw new CliError('参数 --disable 缺少值');
      o.disable = v.split(',').map((s) => s.trim().toUpperCase()).filter(Boolean);
      const bad = o.disable.filter((id) => !RULES[id]);
      if (bad.length) throw new CliError(`未知规则：${bad.join(', ')}（用 --rules 查看）`);
    } else if (a.startsWith('-')) throw new CliError(`未知参数：${a}`);
    else if (dirSet) throw new CliError(`只能指定一个项目目录，多余的：${a}`);
    else { o.dir = a; dirSet = true; }
  }
  return o;
}

function exitCodeFor(result, strict) {
  if (result.summary.error > 0) return 1;
  if (strict && result.summary.warn > 0) return 1;
  return 0;
}

function main(argv = process.argv.slice(2), out = console) {
  let o;
  try {
    o = parseArgs(argv);
  } catch (e) {
    if (e instanceof CliError) { out.error(e.message); return 2; }
    throw e;
  }
  if (o.help) { out.log(HELP); return 0; }
  if (o.rules) { out.log(formatRules()); return 0; }
  let result;
  try {
    result = scan(o.dir, o);
  } catch (e) {
    out.error(e.message);
    return 2;
  }
  if (o.json) out.log(JSON.stringify(result, null, 2));
  else out.log(formatText(result, { color: process.stdout.isTTY && !process.env.NO_COLOR }));
  return exitCodeFor(result, o.strict);
}

module.exports = { parseArgs, main, exitCodeFor, CliError };

// npx 下 bin 是软链接，需比较真实路径
if (require.main && fs.realpathSync(require.main.filename) === fs.realpathSync(__filename)) {
  process.exitCode = main();
}
