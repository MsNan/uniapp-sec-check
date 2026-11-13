'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');
const { parseArgs, main, CliError } = require('../bin/cli');

const CLI = path.join(__dirname, '..', 'bin', 'cli.js');
const FX = path.join(__dirname, 'fixtures');

function capture(argv) {
  const out = [];
  const err = [];
  const code = main(argv, { log: (s) => out.push(s), error: (s) => err.push(s) });
  return { code, out: out.join('\n'), err: err.join('\n') };
}

test('parseArgs：参数解析与报错', () => {
  const o = parseArgs(['proj', '--json', '--strict', '--disable', 'net001,DBG001', '--include-uni-modules']);
  assert.equal(o.dir, 'proj');
  assert.deepEqual(o.disable, ['NET001', 'DBG001']);
  assert.ok(o.json && o.strict && o.includeUniModules);
  assert.throws(() => parseArgs(['--disable']), CliError);
  assert.throws(() => parseArgs(['--disable', 'XYZ999']), /未知规则/);
  assert.throws(() => parseArgs(['--bogus']), /未知参数/);
  assert.throws(() => parseArgs(['a', 'b']), /只能指定一个/);
});

test('退出码：有错误 1，干净 0，--strict 下警告也算，参数错误 2', () => {
  assert.equal(capture([path.join(FX, 'bad-app')]).code, 1);
  assert.equal(capture([path.join(FX, 'clean-app')]).code, 0);
  assert.equal(capture([path.join(FX, 'no-manifest')]).code, 0);
  assert.equal(capture([path.join(FX, 'no-manifest'), '--strict']).code, 1);
  assert.equal(capture(['--wat']).code, 2);
  assert.equal(capture([path.join(FX, 'missing-dir')]).code, 2);
});

test('--json 输出可解析且含 summary / findings', () => {
  const { out } = capture([path.join(FX, 'bad-app'), '--json']);
  const j = JSON.parse(out);
  assert.ok(j.summary.error > 0);
  assert.ok(Array.isArray(j.findings));
  assert.ok(j.findings.every((f) => f.id && f.rule && f.severity && f.message));
});

test('--rules 列出全部规则和来源链接；--help', () => {
  const r = capture(['--rules']);
  assert.match(r.out, /SEC001/);
  assert.match(r.out, /developers\.weixin\.qq\.com/);
  assert.match(capture(['-h']).out, /用法/);
});

test('真实子进程运行（含 realpath 入口判断）', () => {
  const r = spawnSync(process.execPath, [CLI, path.join(FX, 'bad-app')], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /合计：\d+ 错误/);
  const ok = execFileSync(process.execPath, [CLI, path.join(FX, 'clean-app'), '--json'], { encoding: 'utf8' });
  assert.equal(JSON.parse(ok).summary.error, 0);
});
