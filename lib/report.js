'use strict';

const { RULES } = require('./rules');

const ICON = { error: '✖ 错误', warn: '⚠ 警告', info: 'ℹ 提示' };

function formatText(result, { color = false } = {}) {
  const c = (code, s) => (color ? `\u001b[${code}m${s}\u001b[0m` : s);
  const paint = { error: (s) => c(31, s), warn: (s) => c(33, s), info: (s) => c(36, s) };
  const lines = [];
  lines.push(`uniapp-sec-check：${result.root}`);
  lines.push(`manifest：${result.manifest || '（未找到）'}，扫描文本文件 ${result.filesScanned} 个`);
  lines.push('');
  if (!result.findings.length) {
    lines.push('没有发现问题。（只代表本工具的确定性规则没命中，不等于通过审核或绝对安全）');
  }
  for (const f of result.findings) {
    const loc = f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : '(项目)';
    lines.push(`${paint[f.severity](ICON[f.severity])} ${f.id} ${RULES[f.id].title}`);
    lines.push(`   ${loc}`);
    lines.push(`   ${f.message}`);
  }
  lines.push('');
  const s = result.summary;
  lines.push(`合计：${paint.error(s.error + ' 错误')}，${paint.warn(s.warn + ' 警告')}，${paint.info(s.info + ' 提示')}`);
  lines.push('规则依据：uniapp-sec-check --rules；单行忽略：在该行或上一行写注释 sec-check-ignore');
  return lines.join('\n');
}

function formatRules() {
  const lines = ['规则列表（依据链接为微信 / 微信支付 / DCloud 官方文档；hygiene = 工程卫生类，无官方条文）', ''];
  for (const [id, r] of Object.entries(RULES)) {
    lines.push(`${id}  ${r.name}  ${r.title}`);
    if (r.sources.length) for (const s of r.sources) lines.push(`      ${s}`);
    else lines.push(`      (${r.basis})`);
  }
  return lines.join('\n');
}

module.exports = { formatText, formatRules };
