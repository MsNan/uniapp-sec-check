'use strict';

// 去掉注释但保持字符位置和行号不变（注释字符替换成空格，换行保留）。
// 只是确定性的轻量实现：能处理 '' "" `` 字符串和 // /* */ 注释；
// 不解析正则字面量（/http:\/\// 这类极少见写法可能误判，可用 sec-check-ignore 忽略）。

function blank(s) {
  return s.replace(/[^\n]/g, ' ');
}

function stripJsComments(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === '/' && d === '/') {
      let j = src.indexOf('\n', i);
      if (j === -1) j = n;
      out += blank(src.slice(i, j));
      i = j;
    } else if (c === '/' && d === '*') {
      let j = src.indexOf('*/', i + 2);
      j = j === -1 ? n : j + 2;
      out += blank(src.slice(i, j));
      i = j;
    } else if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < n && src[j] !== c) {
        if (src[j] === '\\') j++;
        else if (src[j] === '\n' && c !== '`') break;
        j++;
      }
      out += src.slice(i, j + 1);
      i = j + 1;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

function stripHtmlComments(src) {
  return src.replace(/<!--[\s\S]*?-->/g, blank);
}

// .vue / .nvue：<script> 内按 JS 去注释，其余部分只去 HTML 注释
function stripVueComments(src) {
  const re = /(<script\b[^>]*>)([\s\S]*?)(<\/script>)/gi;
  let out = '';
  let last = 0;
  let m;
  while ((m = re.exec(src))) {
    out += stripHtmlComments(src.slice(last, m.index));
    out += m[1] + stripJsComments(m[2]) + m[3];
    last = m.index + m[0].length;
  }
  out += stripHtmlComments(src.slice(last));
  return out;
}

// uni-app 的 manifest.json / pages.json 允许注释，这里转成标准 JSON 再解析
function parseJsonc(text) {
  let s = text.replace(/^\uFEFF/, '');
  s = stripJsComments(s);
  // 去掉对象/数组结尾多余的逗号（字符串内的不动）
  let out = '';
  let inStr = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      out += c;
      if (c === '\\') { out += s[i + 1] || ''; i++; } else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; out += c; continue; }
    if (c === ',') {
      let j = i + 1;
      while (j < s.length && /\s/.test(s[j])) j++;
      if (s[j] === '}' || s[j] === ']') continue;
    }
    out += c;
  }
  return JSON.parse(out);
}

module.exports = { stripJsComments, stripHtmlComments, stripVueComments, parseJsonc };
