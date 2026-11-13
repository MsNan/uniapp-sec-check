'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { stripJsComments, stripVueComments, parseJsonc } = require('../lib/strip');

test('stripJsComments 去掉注释但保留字符串里的 //，且长度和行号不变', () => {
  const src = "const a = 'https://x.com' // 注释 http://c.com\n/* 块\n注释 */ const b = \"//不是注释\"";
  const out = stripJsComments(src);
  assert.equal(out.length, src.length);
  assert.equal(out.split('\n').length, src.split('\n').length);
  assert.match(out, /'https:\/\/x\.com'/);
  assert.doesNotMatch(out, /c\.com/);
  assert.match(out, /"\/\/不是注释"/);
});

test('stripVueComments：模板 HTML 注释和 script 注释都去掉，模板里的撇号不影响', () => {
  const src = "<template><text>don't</text><!-- <button open-type=\"chooseAvatar\"/> --></template>\n<script>\n// console.log(1)\nconsole.log(2)\n</script>";
  const out = stripVueComments(src);
  assert.doesNotMatch(out, /chooseAvatar/);
  assert.doesNotMatch(out, /console\.log\(1\)/);
  assert.match(out, /console\.log\(2\)/);
  assert.match(out, /don't/);
});

test('parseJsonc 支持注释、尾逗号、BOM，字符串里的 // 和 , 不受影响', () => {
  const j = parseJsonc('\uFEFF{\n // c\n "a": "https://x.com/,]",\n "b": [1,2,],\n}');
  assert.deepEqual(j, { a: 'https://x.com/,]', b: [1, 2] });
});

test('parseJsonc 非法 JSON 抛错', () => {
  assert.throws(() => parseJsonc('{ "a": }'));
});
