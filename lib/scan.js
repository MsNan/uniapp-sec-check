'use strict';

const fs = require('fs');
const path = require('path');
const { stripJsComments, stripVueComments, parseJsonc } = require('./strip');
const { RULES, LOCATION_PRIVATE_INFOS, PRIVACY_API_GROUPS } = require('./rules');

const DEFAULT_IGNORE_DIRS = ['node_modules', 'unpackage', 'dist', '.git', '.hbuilderx', '.idea', '.vscode', 'coverage', 'uni_modules'];
const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx', '.vue', '.nvue', '.uts']);
const TEXT_EXT = new Set([...CODE_EXT, '.json', '.html', '.yml', '.yaml', '.txt', '.md', '.pem', '.key']);
const CERT_EXT = new Set(['.pem', '.p12', '.pfx', '.key', '.crt', '.cer']);
const MAX_SIZE = 1024 * 1024;
const IGNORE_MARK = 'sec-check-ignore';

// ---------- 文件收集 ----------
function isEnvFile(name) {
  return name === '.env' || name.startsWith('.env.');
}

function walk(root, opts = {}) {
  const ignore = new Set(DEFAULT_IGNORE_DIRS);
  if (opts.includeUniModules) ignore.delete('uni_modules');
  const files = [];
  (function rec(dir) {
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    ents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of ents) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!ignore.has(e.name)) rec(p);
      } else if (e.isFile()) {
        files.push(p);
      }
    }
  })(root);
  return files;
}

// ---------- 小工具 ----------
function lineOf(text, index) {
  let n = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

function mask(v) {
  if (v.length <= 6) return '***';
  return v.slice(0, 4) + '***' + `（${v.length} 位）`;
}

function isPlaceholder(v) {
  const s = v.trim();
  return (
    /^(x+|\*+|0+|-+|\.+)$/i.test(s) ||
    /^(your|you_|<|\$\{|\{\{|process\.env|import\.meta)/i.test(s) ||
    /^(changeme|placeholder|todo|null|undefined|none|填写|请填写|你的)/i.test(s)
  );
}

function ignoredLines(raw) {
  const set = new Set();
  const lines = raw.split('\n');
  lines.forEach((l, i) => {
    if (l.includes(IGNORE_MARK)) { set.add(i + 1); set.add(i + 2); }
  });
  return set;
}

// ---------- 规则 ----------
const SECRET_NAME = /(?:^|[^A-Za-z0-9_])["']?((?:wx_?|mp_?|weixin_?)?app_?secret|wx_?secret|mp_?secret|secret_?key|client_?secret|access_?key_?secret|secret)["']?\s*[:=]\s*(["'`])([^"'`\r\n]{8,})\2/gi;
const PAY_NAME = /(?:^|[^A-Za-z0-9_])["']?(api_?v3_?key|apiv3_?key|api_?v2_?key|mch_?key|mch_?secret|merchant_?key|partner_?key|pay_?key|pay_?sign_?key|pay_?secret)["']?\s*[:=]\s*(["'`])([^"'`\r\n]{8,})\2/gi;
const PEM_BLOCK = /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/g;
const ENV_LINE = /^\s*(?:export\s+)?([A-Za-z0-9_]+)\s*=\s*(.*)$/;
const ENV_SECRET_NAME = /(SECRET|APIV3|API_V3|MCH_KEY|MCHKEY|PARTNER_KEY|PAY_KEY|PRIVATE_KEY)/i;

function scanSecrets(rel, raw, add, isClient = true) {
  for (const [re, id] of [[SECRET_NAME, 'SEC001'], [PAY_NAME, 'SEC002']]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(raw))) {
      const value = m[3];
      if (isPlaceholder(value)) continue;
      add(id, 'error', rel, lineOf(raw, m.index + m[0].indexOf(m[1])),
        isClient
          ? `${m[1]} 是写死的字符串 ${mask(value)}。前端/小程序包可以被解包，密钥要放到服务端；已提交过的请立即重置。`
          : `${m[1]} 是写死的字符串 ${mask(value)}。这里不在小程序源码目录，但写死在仓库里同样会泄露，改用服务端环境变量；已提交过的请立即重置。`);
    }
  }
  PEM_BLOCK.lastIndex = 0;
  let m;
  while ((m = PEM_BLOCK.exec(raw))) {
    add('SEC003', 'error', rel, lineOf(raw, m.index), `发现 ${m[0]}：私钥不应出现在前端工程里，已提交过的请作废并更换证书。`);
  }
}

function scanEnv(rel, raw, add) {
  raw.split('\n').forEach((line, i) => {
    const m = ENV_LINE.exec(line);
    if (!m || !ENV_SECRET_NAME.test(m[1])) return;
    const v = m[2].trim().replace(/^["']|["']$/g, '');
    if (!v || isPlaceholder(v)) return;
    const bundled = /^(VITE_|VUE_APP_|UNI_)/.test(m[1]);
    add('SEC005', 'error', rel, i + 1,
      `${m[1]}=${mask(v)}${bundled ? '：这个前缀的变量会被打包进前端代码' : ''}。密钥不要放进前端工程的 .env，放到服务端环境变量。`);
  });
}

const HTTP_RE = /\b(http|ws):\/\/([A-Za-z0-9.\-_]+|\[[0-9a-fA-F:]+\])(:\d+)?/g;
const REQUEST_CONTEXT = /\b(url|baseURL|baseUrl|BASE_URL|base_url|apiBase|API_BASE|request|uploadFile|downloadFile|connectSocket)\b/;

function hostKind(host) {
  const h = host.toLowerCase();
  if (h === 'localhost' || h === '0.0.0.0' || h === '[::1]' || /^127\./.test(h)) return 'loopback';
  if (/^10\./.test(h) || /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h)) return 'lan';
  if (h === 'www.w3.org' || h === 'w3.org') return 'xmlns';
  return 'public';
}

function scanCode(rel, raw, code, ctx, add) {
  const isConfig = /(^|\/)(vite|vue|webpack)\.config\.[cm]?[jt]s$/.test(rel);
  const isMin = /\.min\.js$/.test(rel);

  // SEC006
  let m;
  const wxApi = /api\.weixin\.qq\.com/g;
  while ((m = wxApi.exec(code))) {
    add('SEC006', 'error', rel, lineOf(code, m.index), '微信规定 api.weixin.qq.com 不能配成服务器域名、相关 API 也不能在小程序内调用；AppSecret 和 access_token 只能在服务端用。');
  }

  // NET001
  if (!isConfig && !isMin) {
    HTTP_RE.lastIndex = 0;
    while ((m = HTTP_RE.exec(code))) {
      const kind = hostKind(m[2]);
      if (kind === 'xmlns') continue;
      const line = lineOf(code, m.index);
      const lineText = code.split('\n')[line - 1] || '';
      const scheme = m[1];
      const want = scheme === 'ws' ? 'wss://' : 'https://';
      if (kind === 'loopback') {
        add('NET001', 'warn', rel, line, `${m[0]} 是本机地址：小程序服务器域名不能用 localhost / 本机 IP，上线前确认只在开发环境用。`);
      } else if (kind === 'lan') {
        add('NET001', 'info', rel, line, `${m[0]} 是局域网地址：只适合联调，正式版请换成已备案的 ${want} 域名。`);
      } else {
        const sev = REQUEST_CONTEXT.test(lineText) ? 'error' : 'warn';
        add('NET001', sev, rel, line, `${m[0]}：小程序网络请求只支持 https / wss，并且要在后台配置服务器域名。${sev === 'warn' ? '（这一行不像请求地址，若只是展示文字可忽略）' : ''}`);
      }
    }
  }

  // NET002
  const ssl = /sslVerify\s*:\s*false\b/g;
  while ((m = ssl.exec(code))) {
    add('NET002', 'warn', rel, lineOf(code, m.index), 'sslVerify: false 会关闭 App 安卓端的证书校验（官方文档标注「不推荐」），应改用常见 CA 签发的证书。');
  }

  // DBG003
  const dbg = /\b(?:uni|wx)\.setEnableDebug\s*\(\s*\{[^}]*enableDebug\s*:\s*true/g;
  while ((m = dbg.exec(code))) {
    add('DBG003', 'error', rel, lineOf(code, m.index), 'setEnableDebug({ enableDebug: true }) 对正式版也生效，会给用户打开调试面板。');
  }

  // DBG002 import / new
  const vc = /(?:from\s+|require\(\s*|import\(\s*)['"](vconsole|eruda)['"]|new\s+VConsole\b|\beruda\.init\s*\(/g;
  if ((m = vc.exec(code))) {
    add('DBG002', 'warn', rel, lineOf(code, m.index), `引入了调试面板（${m[1] || m[0].trim()}），上线前确认只在开发环境加载（每个文件只报第一处）。`);
  }

  // DBG001 计数
  if (!isMin && !isConfig) {
    const cl = /\bconsole\.(log|debug)\s*\(/g;
    let c = 0;
    while (cl.exec(code)) c++;
    if (c) ctx.console.push({ file: rel, count: c });
  }

  // 地理位置接口 & 隐私接口
  if (!isMin) {
    const apiRe = /\b(?:uni|wx)\.([A-Za-z]+)\s*\(/g;
    while ((m = apiRe.exec(code))) {
      const api = m[1];
      const line = lineOf(code, m.index);
      if (LOCATION_PRIVATE_INFOS.includes(api)) record(ctx.location, api, rel, line);
      for (const g of PRIVACY_API_GROUPS) if (g.apis && g.apis.includes(api)) record(ctx.privacy, g.info, rel, line, `${api}`);
    }
    const scopeRe = /['"]scope\.([A-Za-z]+)['"]/g;
    while ((m = scopeRe.exec(code))) {
      for (const g of PRIVACY_API_GROUPS) if (g.scopes && g.scopes.includes(m[1])) record(ctx.privacy, g.info, rel, lineOf(code, m.index), `scope.${m[1]}`);
    }
    const otRe = /open-type\s*=\s*["']([A-Za-z|]+)["']/g;
    while ((m = otRe.exec(code))) {
      for (const t of m[1].split('|')) {
        for (const g of PRIVACY_API_GROUPS) if (g.openTypes && g.openTypes.includes(t)) record(ctx.privacy, g.info, rel, lineOf(code, m.index), `open-type=${t}`);
      }
    }
    const nickRe = /<input\b[^>]*\btype\s*=\s*["']nickname["']/g;
    while ((m = nickRe.exec(code))) record(ctx.privacy, '昵称、头像', rel, lineOf(code, m.index), 'input type=nickname');
    const camRe = /<camera\b/g;
    while ((m = camRe.exec(code))) record(ctx.privacy, '摄像头', rel, lineOf(code, m.index), '<camera>');
    if (/\b(?:uni|wx)\.(onNeedPrivacyAuthorization|getPrivacySetting|requirePrivacyAuthorize)\b|agreePrivacyAuthorization/.test(code)) ctx.privacyHandled = true;
  }
}

function record(map, key, file, line, via) {
  if (!map.has(key)) map.set(key, []);
  map.get(key).push({ file, line, via: via || key });
}

// ---------- manifest ----------
function findManifest(root) {
  for (const p of ['manifest.json', 'src/manifest.json']) {
    const f = path.join(root, p);
    if (fs.existsSync(f)) return f;
  }
  return null;
}

function checkManifest(root, ctx, add) {
  const file = findManifest(root);
  if (!file) {
    add('MAN001', 'warn', null, null, '没找到 manifest.json（根目录或 src/ 下），跳过 manifest 相关检查。确认目录是 uni-app 项目。');
    return null;
  }
  const rel = path.relative(root, file).split(path.sep).join('/');
  let json;
  try {
    json = parseJsonc(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    add('MAN001', 'error', rel, null, `manifest.json 解析失败：${e.message}`);
    return { rel, json: null, mp: null };
  }
  const mp = json['mp-weixin'];
  if (!mp || typeof mp !== 'object') {
    add('MAN001', 'info', rel, null, 'manifest.json 没有 mp-weixin 配置，跳过微信小程序相关检查。');
    return { rel, json, mp: null };
  }
  if (!mp.appid || !String(mp.appid).trim()) {
    add('MAN002', 'warn', rel, null, 'mp-weixin.appid 为空：上传/发布正式版需要填写自己的小程序 AppID（AppID 不是密钥，可以提交；AppSecret 不行）。');
  }
  if (mp.setting && mp.setting.urlCheck === false) {
    add('NET003', 'warn', rel, null, 'mp-weixin.setting.urlCheck 为 false：开发者工具不校验域名/TLS，手机关闭调试后可能请求失败。上线前配置好服务器域名并打开校验测试。');
  }
  if ('__usePrivacyCheck__' in mp) {
    add('MAN007', 'info', rel, null, '__usePrivacyCheck__ 只在 2023-10-17 前用于提前启用隐私功能，现在不论是否配置隐私功能都已启用，可以删掉。');
  }
  const perm = mp.permission && typeof mp.permission === 'object' ? mp.permission : {};
  for (const [scope, obj] of Object.entries(perm)) {
    const desc = obj && typeof obj === 'object' ? obj.desc : undefined;
    if (typeof desc !== 'string' || !desc.trim()) {
      add('MAN003', 'error', rel, null, `permission["${scope}"] 缺少 desc（用途说明，必填）。`);
    } else if ([...desc].length > 30) {
      add('MAN003', 'warn', rel, null, `permission["${scope}"].desc 有 ${[...desc].length} 个字，微信文档要求最长 30 个字符。`);
    }
  }
  const declared = Array.isArray(mp.requiredPrivateInfos) ? mp.requiredPrivateInfos : [];
  for (const v of declared) {
    if (!LOCATION_PRIVATE_INFOS.includes(v)) {
      add('MAN005', 'warn', rel, null, `requiredPrivateInfos 里的 "${v}" 不是支持的值（只支持 ${LOCATION_PRIVATE_INFOS.join(' / ')}）。`);
    } else if (!ctx.location.has(v)) {
      add('MAN005', 'info', rel, null, `requiredPrivateInfos 声明了 ${v}，但源码里没扫到调用（可能在 uni_modules/插件里，确认后再删）。`);
    }
  }
  for (const [api, uses] of ctx.location) {
    if (!declared.includes(api)) {
      const u = uses[0];
      add('MAN004', 'error', u.file, u.line, `用了 ${api}（共 ${uses.length} 处），但 manifest.json 的 mp-weixin.requiredPrivateInfos 没有声明，2022-07-14 后发布的小程序会无法调用。`);
    }
  }
  const precise = ['getLocation', 'startLocationUpdate', 'startLocationUpdateBackground', 'onLocationChange'].filter((a) => ctx.location.has(a));
  if (precise.length && !perm['scope.userLocation']) {
    const u = ctx.location.get(precise[0])[0];
    add('MAN006', 'warn', u.file, u.line, `用了 ${precise.join(' / ')}，但 mp-weixin.permission 里没有 "scope.userLocation": { "desc": "..." }（uni-app 文档：申请位置权限必须填此处）。`);
  }
  return { rel, json, mp };
}

// ---------- 主入口 ----------
function scan(dir, opts = {}) {
  const root = path.resolve(dir);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    throw new Error(`目录不存在：${dir}`);
  }
  const disabled = new Set((opts.disable || []).map((s) => s.toUpperCase()));
  const findings = [];
  let currentIgnore = null;
  const add = (id, severity, file, line, message) => {
    if (disabled.has(id)) return;
    if (currentIgnore && file === currentIgnore.file && line && currentIgnore.lines.has(line)) return;
    findings.push({ id, rule: RULES[id].name, severity, file, line, message });
  };
  const ctx = { console: [], location: new Map(), privacy: new Map(), privacyHandled: false };
  const files = walk(root, opts);
  let scanned = 0;
  // 代码类规则（http、调试、隐私/定位接口）只看 manifest 所在目录：
  // Vite/CLI 项目是 src/，同仓库里的 server/、scripts/、tests/ 不会打进小程序包。
  // 密钥、证书、.env 规则仍扫整个项目。
  const mf = findManifest(root);
  const codeRoot = mf ? path.dirname(mf) : root;
  const inCodeRoot = (f) => codeRoot === root || f.startsWith(codeRoot + path.sep);

  for (const f of files) {
    const rel = path.relative(root, f).split(path.sep).join('/');
    const base = path.basename(f);
    const ext = path.extname(f).toLowerCase();

    if (CERT_EXT.has(ext) || /^apiclient_(key|cert)\./i.test(base)) {
      const sev = /^apiclient_/i.test(base) || ext === '.p12' || ext === '.pfx' || ext === '.key' ? 'error' : 'warn';
      add('SEC004', sev, rel, null, `${base}：证书/私钥文件不应放在前端工程（会被打包或提交）。${/^apiclient_/i.test(base) ? '这是微信支付商户 API 证书的默认文件名。' : ''}`);
    }

    const env = isEnvFile(base);
    if (!env && !TEXT_EXT.has(ext)) continue;
    let st;
    try { st = fs.statSync(f); } catch { continue; }
    if (st.size > MAX_SIZE) continue;
    const raw = fs.readFileSync(f, 'utf8');
    scanned++;
    currentIgnore = { file: rel, lines: ignoredLines(raw) };

    if (env) { scanEnv(rel, raw, add); continue; }
    scanSecrets(rel, raw, add, inCodeRoot(f));
    if (base === 'package.json' && path.dirname(f) === root) {
      try {
        const pkg = JSON.parse(raw);
        for (const name of ['vconsole', 'eruda']) {
          if ((pkg.dependencies || {})[name]) add('DBG002', 'warn', rel, null, `dependencies 里有 ${name}，会被打进产物；只在开发用请移到 devDependencies 并按环境加载。`);
        }
      } catch { /* 非法 package.json 交给 npm 报错 */ }
    }
    if (CODE_EXT.has(ext) && (inCodeRoot(f) || /(^|\/)(vite|vue)\.config\.[cm]?[jt]s$/.test(rel))) {
      const code = ext === '.vue' || ext === '.nvue' ? stripVueComments(raw) : stripJsComments(raw);
      scanCode(rel, raw, code, ctx, add);
    }
  }
  currentIgnore = null;

  // DBG001 汇总成一条
  if (ctx.console.length) {
    const total = ctx.console.reduce((s, x) => s + x.count, 0);
    const top = ctx.console.slice().sort((a, b) => b.count - a.count).slice(0, 5).map((x) => `${x.file}(${x.count})`).join('、');
    const dropped = files.some((f) => /(^|[\\/])vite\.config\.[cm]?[jt]s$/.test(f) && /drop_console\s*:\s*true|\bdrop\s*:[^\n]*['"]console['"]/.test(fs.readFileSync(f, 'utf8')));
    add('DBG001', dropped ? 'info' : 'warn', null, null,
      `源码里有 ${total} 处 console.log/debug：${top}。${dropped ? 'vite 配置里已在构建时移除 console。' : '上线前清理，或在构建配置里移除（如 esbuild drop / terser drop_console）。'}`);
  }

  const manifest = checkManifest(root, ctx, add);

  // PRV001 每类隐私信息一条
  for (const [info, uses] of ctx.privacy) {
    const where = uses.slice(0, 3).map((u) => `${u.file}:${u.line} ${u.via}`).join('；');
    add('PRV001', 'info', uses[0].file, uses[0].line,
      `用到「${info}」相关接口（${uses.length} 处：${where}${uses.length > 3 ? ' …' : ''}）。需在小程序后台《用户隐私保护指引》声明，否则会报 errno 112。${ctx.privacyHandled ? '已检测到隐私授权处理代码。' : '未检测到 onNeedPrivacyAuthorization / getPrivacySetting，将由微信官方隐私弹窗兜底。'}`);
  }

  const order = { error: 0, warn: 1, info: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.id.localeCompare(b.id) || String(a.file).localeCompare(String(b.file)) || (a.line || 0) - (b.line || 0));
  const summary = { error: 0, warn: 0, info: 0 };
  for (const x of findings) summary[x.severity]++;
  return { root, manifest: manifest ? manifest.rel : null, filesScanned: scanned, summary, findings };
}

module.exports = { scan, walk, hostKind, isPlaceholder, mask, DEFAULT_IGNORE_DIRS };
