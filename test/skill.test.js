'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { RULES } = require('../lib/rules');

test('SKILL.md：frontmatter 的 name 与目录名一致，description 非空，引用的规则 ID 都存在', () => {
  const dir = path.join(__dirname, '..', 'skills', 'uniapp-sec-check');
  const text = fs.readFileSync(path.join(dir, 'SKILL.md'), 'utf8');
  const fm = text.match(/^---\n([\s\S]*?)\n---\n/);
  assert.ok(fm, '缺少 frontmatter');
  const name = fm[1].match(/^name:\s*(.+)$/m)[1].trim();
  assert.equal(name, path.basename(dir));
  assert.match(name, /^[a-z0-9-]+$/);
  assert.ok(fm[1].match(/^description:\s*(.+)$/m)[1].trim().length > 20);
  for (const id of new Set(text.match(/\b[A-Z]{3}\d{3}\b/g))) assert.ok(RULES[id], `未知规则 ${id}`);
});

test('每条规则都有官方来源或标为 hygiene', () => {
  for (const [id, r] of Object.entries(RULES)) {
    assert.ok(r.sources.length > 0 || r.basis === 'hygiene', id);
    for (const s of r.sources) assert.match(s, /^https:\/\/(developers\.weixin\.qq\.com|pay\.weixin\.qq\.com|uniapp\.dcloud\.net\.cn)\//, id);
  }
});
