'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scan, hostKind, isPlaceholder, mask } = require('../lib/scan');

const FX = path.join(__dirname, 'fixtures');
const bad = scan(path.join(FX, 'bad-app'));
const ids = (r, sev) => r.findings.filter((f) => !sev || f.severity === sev).map((f) => f.id);
const find = (r, id, pred = () => true) => r.findings.filter((f) => f.id === id && pred(f));

function tmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'usc-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  return dir;
}

test('bad-app：命中全部预期错误', () => {
  for (const id of ['SEC001', 'SEC002', 'SEC003', 'SEC004', 'SEC005', 'SEC006', 'NET001', 'MAN003', 'MAN004', 'DBG003']) {
    assert.ok(ids(bad, 'error').includes(id), `缺少错误 ${id}`);
  }
  assert.equal(bad.summary.error, ids(bad, 'error').length);
});

test('密钥：写死的 AppSecret / APIv3 key 报错，占位符 your_xxx 不报，输出里值被打码', () => {
  const s1 = find(bad, 'SEC001');
  assert.equal(s1.length, 1);
  assert.equal(s1[0].file, 'config/wx.js');
  assert.equal(s1[0].line, 4);
  assert.equal(find(bad, 'SEC002').length, 1);
  assert.ok(!bad.findings.some((f) => /mchKey/.test(f.message)));
  const json = JSON.stringify(bad);
  assert.ok(!json.includes('FAKE_APPSECRET_FOR_TESTS_ONLY'));
  assert.ok(!json.includes('FAKE_APIV3_KEY_FOR_TESTS_ONLY'));
  assert.ok(!json.includes('FAKE_ENV_SECRET_FOR_TESTS'));
});

test('默认跳过 node_modules / unpackage / uni_modules', () => {
  assert.ok(!bad.findings.some((f) => f.file && /node_modules|unpackage|uni_modules/.test(f.file)));
  assert.ok(!bad.findings.some((f) => /chooseLocation/.test(f.message) && f.id === 'MAN004'));
});

test('--include-uni-modules 时扫描 uni_modules，插件里的 chooseLocation 也要求声明', () => {
  const r = scan(path.join(FX, 'bad-app'), { includeUniModules: true });
  const m = find(r, 'MAN004', (f) => /chooseLocation/.test(f.message));
  assert.equal(m.length, 1);
  assert.match(m[0].file, /^uni_modules\//);
});

test('.env：VITE_ 前缀密钥报错并提示会被打包，空值不报，非密钥变量不报', () => {
  const e = find(bad, 'SEC005');
  assert.equal(e.length, 1);
  assert.equal(e[0].line, 2);
  assert.match(e[0].message, /打包进前端/);
});

test('http：请求地址报错、展示文字警告、本机警告、局域网提示、w3 命名空间和注释忽略', () => {
  const n = find(bad, 'NET001');
  const by = (s) => n.filter((f) => f.message.includes(s));
  assert.equal(by('api.example.com')[0].severity, 'error');
  assert.equal(by('help.example.com')[0].severity, 'warn');
  assert.equal(by('localhost:8080')[0].severity, 'warn');
  assert.equal(by('192.168.1.10')[0].severity, 'info');
  assert.equal(by('w3.org').length, 0);
  assert.equal(by('commented.example.com').length, 0);
});

test('sec-check-ignore 注释忽略该行', () => {
  assert.equal(find(bad, 'NET001', (f) => f.message.includes('legacy.example.com')).length, 0);
});

test('sslVerify:false 警告，api.weixin.qq.com 报错', () => {
  assert.equal(find(bad, 'NET002')[0].line, 10);
  assert.equal(find(bad, 'SEC006')[0].file, 'utils/request.js');
});

test('manifest：appid 为空、urlCheck 关闭、__usePrivacyCheck__ 过时', () => {
  assert.equal(find(bad, 'MAN002')[0].severity, 'warn');
  assert.equal(find(bad, 'NET003')[0].severity, 'warn');
  assert.equal(find(bad, 'MAN007')[0].severity, 'info');
});

test('manifest：permission 缺 desc 报错，超过 30 字警告', () => {
  const m = find(bad, 'MAN003');
  assert.equal(m.find((f) => f.message.includes('scope.userLocation')).severity, 'error');
  assert.equal(m.find((f) => f.message.includes('scope.userFuzzyLocation')).severity, 'warn');
});

test('requiredPrivateInfos：未声明的 getLocation 报错；未知值警告；没用到的提示', () => {
  const miss = find(bad, 'MAN004');
  assert.equal(miss.length, 1);
  assert.match(miss[0].message, /getLocation/);
  assert.equal(miss[0].file, 'pages/index/index.vue');
  const extra = find(bad, 'MAN005');
  assert.equal(extra.find((f) => f.message.includes('getFoo')).severity, 'warn');
  assert.equal(extra.find((f) => f.message.includes('声明了 chooseAddress')).severity, 'info');
});

test('MAN006：用了 getLocation 但完全没有 scope.userLocation 时警告', () => {
  const dir = tmpProject({
    'manifest.json': JSON.stringify({ 'mp-weixin': { appid: 'wxFAKEAPPID000000', requiredPrivateInfos: ['getLocation'] } }),
    'pages/a.vue': '<script>\nuni.getLocation({})\n</script>',
  });
  const r = scan(dir);
  assert.equal(find(r, 'MAN006').length, 1);
  assert.equal(find(r, 'MAN004').length, 0);
});

test('隐私接口：按信息类型汇总，注释里的 open-type 不算，未检测到隐私处理时提示官方弹窗兜底', () => {
  const p = find(bad, 'PRV001');
  const infos = p.map((f) => f.message.match(/「(.+?)」/)[1]).sort();
  assert.deepEqual(infos, ['位置信息', '手机号', '选中的照片或视频'].sort());
  assert.ok(p.every((f) => f.severity === 'info' && /官方隐私弹窗兜底/.test(f.message)));
});

test('隐私接口：剪切板、scope 字符串、昵称输入框、camera 组件', () => {
  const dir = tmpProject({
    'manifest.json': '{ "mp-weixin": { "appid": "wxFAKEAPPID000000" } }',
    'pages/a.vue': '<template><input type="nickname"/><camera/></template>\n<script>\nwx.getClipboardData({})\nuni.authorize({ scope: "scope.record" })\n</script>',
  });
  const infos = find(scan(dir), 'PRV001').map((f) => f.message.match(/「(.+?)」/)[1]).sort();
  assert.deepEqual(infos, ['剪切板', '摄像头', '昵称、头像', '麦克风'].sort());
});

test('调试：setEnableDebug(true) 报错、false 不报；vconsole 每文件一条 + dependencies 一条', () => {
  assert.equal(find(bad, 'DBG003').length, 1);
  const d = find(bad, 'DBG002');
  assert.equal(d.length, 2);
  const dir = tmpProject({ 'manifest.json': '{}', 'main.js': 'wx.setEnableDebug({ enableDebug: false })' });
  assert.equal(find(scan(dir), 'DBG003').length, 0);
});

test('console.log：汇总成一条并计数，注释里的不算；vite 配了 drop console 时降为提示', () => {
  const c = find(bad, 'DBG001');
  assert.equal(c.length, 1);
  assert.equal(c[0].severity, 'warn');
  assert.match(c[0].message, /2 处/);
  const clean = scan(path.join(FX, 'clean-app'));
  assert.equal(find(clean, 'DBG001')[0].severity, 'info');
});

test('clean-app（src/manifest.json 布局）没有错误和警告', () => {
  const r = scan(path.join(FX, 'clean-app'));
  assert.equal(r.manifest, 'src/manifest.json');
  assert.equal(r.summary.error, 0);
  assert.equal(r.summary.warn, 0);
  assert.match(find(r, 'PRV001')[0].message, /已检测到隐私授权处理代码/);
});

test('没有 manifest 警告；manifest 语法错误报错', () => {
  assert.equal(find(scan(path.join(FX, 'no-manifest')), 'MAN001')[0].severity, 'warn');
  const b = scan(path.join(FX, 'broken-manifest'));
  assert.equal(find(b, 'MAN001')[0].severity, 'error');
  assert.equal(b.manifest, 'manifest.json');
});

test('disable 关闭指定规则', () => {
  const r = scan(path.join(FX, 'bad-app'), { disable: ['NET001', 'dbg001'] });
  assert.equal(find(r, 'NET001').length, 0);
  assert.equal(find(r, 'DBG001').length, 0);
});

test('证书文件：apiclient_* / .p12 报错，普通 .crt 警告', () => {
  const dir = tmpProject({ 'manifest.json': '{}', 'a/apiclient_cert.p12': 'x', 'b/server.crt': 'x' });
  const s = find(scan(dir), 'SEC004');
  assert.equal(s.find((f) => f.file === 'a/apiclient_cert.p12').severity, 'error');
  assert.equal(s.find((f) => f.file === 'b/server.crt').severity, 'warn');
});

test('结果顺序稳定：错误在前，同级按规则 ID', () => {
  const order = { error: 0, warn: 1, info: 2 };
  for (let i = 1; i < bad.findings.length; i++) {
    const a = bad.findings[i - 1];
    const b = bad.findings[i];
    assert.ok(order[a.severity] < order[b.severity] || (a.severity === b.severity && a.id <= b.id));
  }
  assert.deepEqual(scan(path.join(FX, 'bad-app')), bad);
});

test('工具函数：hostKind / isPlaceholder / mask', () => {
  assert.equal(hostKind('127.0.0.1'), 'loopback');
  assert.equal(hostKind('172.20.0.5'), 'lan');
  assert.equal(hostKind('172.40.0.5'), 'public');
  assert.ok(isPlaceholder('your_app_secret'));
  assert.ok(isPlaceholder('xxxxxxxx'));
  assert.ok(!isPlaceholder('FAKE_APPSECRET_FOR_TESTS_ONLY'));
  assert.equal(mask('abcdefghij'), 'abcd***（10 位）');
});

test('目录不存在时抛错', () => {
  assert.throws(() => scan(path.join(FX, 'nope')), /目录不存在/);
});

test('src/manifest.json 布局：代码类规则只看 src/，密钥规则仍扫整个项目', () => {
  const dir = tmpProject({
    'src/manifest.json': '{ "mp-weixin": { "appid": "wxFAKEAPPID000000" } }',
    'src/api.js': "export const BASE = 'http://api.example.com'",
    'server/index.js': "const url = 'http://api.example.com'\nconsole.log(url)\nconst appSecret = 'FAKE_SERVER_SIDE_SECRET_X'",
  });
  const r = scan(dir);
  assert.deepEqual(find(r, 'NET001').map((f) => f.file), ['src/api.js']);
  assert.equal(find(r, 'DBG001').length, 0);
  const sec = find(r, 'SEC001');
  assert.deepEqual(sec.map((f) => f.file), ['server/index.js']);
  assert.match(sec[0].message, /不在小程序源码目录/);
});
