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

function uniBase(extra = {}) {
  return Object.assign({
    'manifest.json': '{ "mp-weixin": { "appid": "wxFAKEAPPID000000" } }',
    'pages/index/index.vue': '<template><view>ok</view></template>',
  }, extra);
}

test('PAG001：uni-app 缺 pages.json 警告；无 manifest 且无 pages/app.json 不报 PAG001', () => {
  const dir = tmpProject({ 'manifest.json': '{ "mp-weixin": { "appid": "wxFAKEAPPID000000" } }' });
  const miss = find(scan(dir), 'PAG001');
  assert.equal(miss.length, 1);
  assert.equal(miss[0].severity, 'warn');
  const r = scan(path.join(FX, 'no-manifest'));
  assert.equal(find(r, 'PAG001').length, 0);
  assert.equal(find(r, 'MAN001').length, 1);
});

test('PAG001：pages.json 非法 JSONC 报错', () => {
  const dir = tmpProject(uniBase({ 'pages.json': '{ pages: [ }' }));
  const f = find(scan(dir), 'PAG001');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'error');
  assert.equal(f[0].file, 'pages.json');
});

test('PAG002：pages 缺失或空数组或非法项报错', () => {
  const missing = tmpProject(uniBase({ 'pages.json': '{ }' }));
  assert.equal(find(scan(missing), 'PAG002').length, 1);
  const empty = tmpProject(uniBase({ 'pages.json': '{ "pages": [] }' }));
  assert.equal(find(scan(empty), 'PAG002').length, 1);
  const badItem = tmpProject(uniBase({ 'pages.json': '{ "pages": [123, { "path": "" }] }' }));
  assert.ok(find(scan(badItem), 'PAG002').length >= 2);
});

test('PAG003：配置了页面但没有对应文件报错；存在 .nvue 则通过', () => {
  const miss = tmpProject(uniBase({
    'pages.json': '{ "pages": ["pages/index/index", "pages/gone/gone"] }',
  }));
  const f = find(scan(miss), 'PAG003');
  assert.equal(f.length, 1);
  assert.match(f[0].message, /pages\/gone\/gone/);
  const nvue = tmpProject(uniBase({
    'pages.json': '{ "pages": ["pages/n/n"] }',
    'pages/n/n.nvue': '<template><view>n</view></template>',
  }));
  const r = scan(nvue);
  assert.equal(find(r, 'PAG003').length, 0);
  assert.equal(find(r, 'PAG002').length, 0);
});

test('PAG004：主包与分包出现同一路径报错', () => {
  const dir = tmpProject(uniBase({
    'pages.json': JSON.stringify({
      pages: [{ path: 'pages/index/index' }, { path: 'pagesA/list/list' }],
      subPackages: [{ root: 'pagesA', pages: [{ path: 'list/list' }] }],
    }),
    'pagesA/list/list.vue': '<template><view>l</view></template>',
  }));
  const f = find(scan(dir), 'PAG004');
  assert.equal(f.length, 1);
  assert.match(f[0].message, /pagesA\/list\/list/);
});

test('PAG006：分包路径写成全路径或带 root 前缀报错；相对路径通过', () => {
  const bad = tmpProject(uniBase({
    'pages.json': JSON.stringify({
      pages: [{ path: 'pages/index/index' }],
      subPackages: [{ root: 'pagesA', pages: ['pagesA/list/list'] }],
    }),
    'pagesA/list/list.vue': '<template><view>l</view></template>',
  }));
  const f = find(scan(bad), 'PAG006');
  assert.equal(f.length, 1);
  assert.match(f[0].message, /相对路径，不是全路径/);
  const ok = tmpProject(uniBase({
    'pages.json': JSON.stringify({
      pages: [{ path: 'pages/index/index' }],
      subPackages: [{ root: 'pagesA', pages: ['list/list'] }],
    }),
    'pagesA/list/list.vue': '<template><view>l</view></template>',
  }));
  const r = scan(ok);
  assert.equal(find(r, 'PAG006').length, 0);
  assert.equal(find(r, 'PAG003').length, 0);
});

test('PAG007：根目录嵌套或 name 重复报错；package 与 packageA 不算嵌套', () => {
  const nested = tmpProject(uniBase({
    'pages.json': JSON.stringify({
      pages: [{ path: 'pages/index/index' }],
      subPackages: [
        { root: 'pkg', pages: ['a/a'] },
        { root: 'pkg/sub', pages: ['b/b'] },
      ],
    }),
    'pkg/a/a.vue': '<template><view>a</view></template>',
    'pkg/sub/b/b.vue': '<template><view>b</view></template>',
  }));
  const n = find(scan(nested), 'PAG007');
  assert.equal(n.length, 1);
  assert.match(n[0].message, /根目录不能是另外一个 subPackages 内的子目录/);
  const ok = tmpProject(uniBase({
    'pages.json': JSON.stringify({
      pages: [{ path: 'pages/index/index' }],
      subPackages: [
        { root: 'package', pages: ['a/a'] },
        { root: 'packageA', pages: ['b/b'] },
      ],
    }),
    'package/a/a.vue': '<template><view>a</view></template>',
    'packageA/b/b.vue': '<template><view>b</view></template>',
  }));
  assert.equal(find(scan(ok), 'PAG007').length, 0);
  const dupName = tmpProject(uniBase({
    'pages.json': JSON.stringify({
      pages: [{ path: 'pages/index/index' }],
      subPackages: [
        { root: 'pkgA', name: 'same', pages: ['a/a'] },
        { root: 'pkgB', name: 'same', pages: ['b/b'] },
      ],
    }),
    'pkgA/a/a.vue': '<template><view>a</view></template>',
    'pkgB/b/b.vue': '<template><view>b</view></template>',
  }));
  const d = find(scan(dupName), 'PAG007');
  assert.equal(d.length, 1);
  assert.match(d[0].message, /same/);
});

test('PAG008：tabBar 页面只在分包时报错；在主包则通过', () => {
  const files = {
    'pages/home/home.vue': '<template><view>h</view></template>',
    'pagesA/list/list.vue': '<template><view>l</view></template>',
  };
  const bad = tmpProject(uniBase(Object.assign({
    'pages.json': JSON.stringify({
      pages: [{ path: 'pages/index/index' }, { path: 'pages/home/home' }],
      subPackages: [{ root: 'pagesA', pages: ['list/list'] }],
      tabBar: { list: [{ pagePath: 'pages/index/index', text: '首页' }, { pagePath: 'pagesA/list/list', text: '列表' }] },
    }),
  }, files)));
  const f = find(scan(bad), 'PAG008');
  assert.equal(f.length, 1);
  assert.match(f[0].message, /必须在主包内/);
  const ok = tmpProject(uniBase(Object.assign({
    'pages.json': JSON.stringify({
      pages: [{ path: 'pages/index/index' }, { path: 'pages/home/home' }],
      subPackages: [{ root: 'pagesA', pages: ['list/list'] }],
      tabBar: { list: [{ pagePath: 'pages/index/index', text: '首页' }, { pagePath: 'pages/home/home', text: '我的' }] },
    }),
  }, files)));
  const r = scan(ok);
  assert.equal(find(r, 'PAG008').length, 0);
  assert.equal(find(r, 'PAG009').length, 0);
});

test('PAG009：tabBar.list 长度为 1 或 6 报错；2 个通过', () => {
  const twoPages = {
    'pages/home/home.vue': '<template><view>h</view></template>',
  };
  const one = tmpProject(uniBase(Object.assign({
    'pages.json': JSON.stringify({
      pages: [{ path: 'pages/index/index' }],
      tabBar: { list: [{ pagePath: 'pages/index/index', text: '首页' }] },
    }),
  }, twoPages)));
  assert.equal(find(scan(one), 'PAG009').length, 1);
  const paths = ['pages/index/index', 'pages/home/home', 'pages/c/c', 'pages/d/d', 'pages/e/e', 'pages/f/f'];
  const extra = {};
  for (const pth of paths.slice(1)) extra[pth + '.vue'] = '<template><view>x</view></template>';
  const six = tmpProject(uniBase(Object.assign({
    'pages.json': JSON.stringify({
      pages: paths,
      tabBar: { list: paths.map((p) => ({ pagePath: p, text: p })) },
    }),
  }, extra)));
  assert.equal(find(scan(six), 'PAG009').length, 1);
  const two = tmpProject(uniBase(Object.assign({
    'pages.json': JSON.stringify({
      pages: [{ path: 'pages/index/index' }, { path: 'pages/home/home' }],
      tabBar: { list: [{ pagePath: 'pages/index/index', text: '首页' }, { pagePath: 'pages/home/home', text: '我的' }] },
    }),
  }, twoPages)));
  assert.equal(find(scan(two), 'PAG009').length, 0);
});

test('PAG010/PAG011/PAG012：preloadRule 未知页面、未知分包、非法 network 报错；合法配置沉默', () => {
  const bad = tmpProject(uniBase({
    'pages.json': JSON.stringify({
      pages: [{ path: 'pages/index/index' }],
      subPackages: [{ root: 'pagesA', name: 'pkgA', pages: ['list/list'] }],
      preloadRule: {
        'pages/no-such/no-such': { packages: ['no-such'], network: '4g' },
      },
    }),
    'pagesA/list/list.vue': '<template><view>l</view></template>',
  }));
  const r = scan(bad);
  assert.equal(find(r, 'PAG010').length, 1);
  assert.equal(find(r, 'PAG011').length, 1);
  assert.equal(find(r, 'PAG012').length, 1);
  const ok = tmpProject(uniBase({
    'pages.json': JSON.stringify({
      pages: [{ path: 'pages/index/index' }],
      subPackages: [{ root: 'pagesA', name: 'pkgA', pages: ['list/list'] }],
      preloadRule: {
        'pages/index/index': { packages: ['__APP__', 'pagesA'], network: 'all' },
        'pagesA/list/list': { packages: ['pkgA'], network: 'wifi' },
      },
    }),
    'pagesA/list/list.vue': '<template><view>l</view></template>',
  }));
  const s = scan(ok);
  assert.equal(find(s, 'PAG010').length, 0);
  assert.equal(find(s, 'PAG011').length, 0);
  assert.equal(find(s, 'PAG012').length, 0);
});

test('src/ 布局：pages.json 与页面文件按配置文件所在目录解析', () => {
  const clean = scan(path.join(FX, 'clean-app'));
  assert.equal(find(clean, 'PAG001').length, 0);
  assert.equal(find(clean, 'PAG002').length, 0);
  assert.equal(find(clean, 'PAG003').length, 0);
  const dir = tmpProject({
    'src/manifest.json': '{ "mp-weixin": { "appid": "wxFAKEAPPID000000" } }',
    'src/pages.json': '{ "pages": [{ "path": "pages/index/index" }] }',
    'src/pages/index/index.vue': '<template><view>ok</view></template>',
  });
  const r = scan(dir);
  assert.equal(r.summary.error, 0);
  assert.equal(find(r, 'PAG003').length, 0);
});

test('原生 app.json 字符串 pages 可用，无 manifest 时不报 PAG001', () => {
  const dir = tmpProject({
    'app.json': JSON.stringify({ pages: ['pages/index/index'] }),
    'pages/index/index.js': 'Page({})',
  });
  const r = scan(dir);
  assert.equal(find(r, 'PAG001').length, 0);
  assert.equal(find(r, 'PAG002').length, 0);
  assert.equal(find(r, 'PAG003').length, 0);
  assert.equal(find(r, 'MAN001')[0].severity, 'warn');
});

test('subpackages 小写别名可用；同时存在两个字段时警告并采用 subPackages', () => {
  const lower = tmpProject(uniBase({
    'pages.json': JSON.stringify({
      pages: [{ path: 'pages/index/index' }],
      subpackages: [{ root: 'pagesA', pages: ['list/list'] }],
    }),
    'pagesA/list/list.vue': '<template><view>l</view></template>',
  }));
  const a = scan(lower);
  assert.equal(find(a, 'PAG001').length, 0);
  assert.equal(find(a, 'PAG005').length, 0);
  assert.equal(find(a, 'PAG006').length, 0);
  assert.equal(find(a, 'PAG003').length, 0);
  const both = tmpProject(uniBase({
    'pages.json': JSON.stringify({
      pages: [{ path: 'pages/index/index' }],
      subPackages: [{ root: 'pagesA', pages: ['list/list'] }],
      subpackages: [{ root: 'pagesB', pages: ['x/x'] }],
    }),
    'pagesA/list/list.vue': '<template><view>l</view></template>',
  }));
  const b = scan(both);
  const w = find(b, 'PAG001');
  assert.equal(w.length, 1);
  assert.equal(w[0].severity, 'warn');
  // 采用 subPackages，不会去解析 pagesB（也就不会因缺文件报 PAG003）
  assert.equal(find(b, 'PAG003').length, 0);
});

test('PAG005：分包缺少 root 或 pages 不是数组报错', () => {
  const dir = tmpProject(uniBase({
    'pages.json': JSON.stringify({
      pages: [{ path: 'pages/index/index' }],
      subPackages: [{ pages: ['a/a'] }, { root: 'pagesA', pages: 'list/list' }],
    }),
  }));
  const f = find(scan(dir), 'PAG005');
  assert.equal(f.length, 2);
});
