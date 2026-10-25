// 包装toolが使うJS（ES module）の依存specifier抽出。標準JSだけの字句解析で、import時の副作用0・評価0。
//   - code・comment・文字列・正規表現・template本文を区別する。template本文の文字（browser向けscriptの `import … from '…'` 等）は
//     依存にしない。template式 `${…}` の中は通常のcodeとして同じ規則で検査する。
//   - 抽出: static import（両quote・side-effect形）、`export … from`（`*`・`* as`・`{…}`）、固定形の `requireCjs('<依存>')`。
//   - 拒否（fail closed）: dynamic `import(`、`require(`、他形の `requireCjs`、解析できないimport/export形、escape入りspecifier、
//     閉じていない文字列・comment・template・正規表現、未知の文字。迷う形を黙って省略しない。
//   - 失敗は固定codeの `ModuleScanError` だけ（入力の値・位置を持たない）。

export class ModuleScanError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ModuleScanError';
    this.code = code;
  }
}
const fail = (code) => {
  throw new ModuleScanError(code);
};

const PUNCTUATORS = Object.freeze([
  '>>>=', '...', '===', '!==', '**=', '<<=', '>>=', '>>>', '&&=', '||=', '??=',
  '=>', '==', '!=', '<=', '>=', '&&', '||', '??', '?.', '++', '--', '+=', '-=', '*=', '%=', '&=', '|=', '^=', '**', '<<', '>>',
  '{', '}', '(', ')', '[', ']', ';', ',', '<', '>', '+', '-', '*', '%', '&', '|', '^', '!', '~', '?', ':', '=', '.', '@',
]);
/** 直後の `/` を正規表現として読むkeyword。 */
const REGEX_AFTER_WORDS = new Set(['return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'throw', 'case', 'do', 'else', 'yield', 'await']);
const ID_START = /[\p{ID_Start}$_]/u;
const ID_PART = /[\p{ID_Continue}$‌‍]/u;
const LINE_BREAK = new RegExp(`[\n\r${String.fromCharCode(0x2028, 0x2029)}]`);

/** codeのtokenだけを返す（comment・空白は捨てる。templateは本文を捨て、式の中のtokenを順に並べ、全体を1つの値tokenとして扱う）。 */
export function tokenize(text) {
  if (typeof text !== 'string') fail('scan_invalid');
  const tokens = [];
  const braces = [];
  let i = 0;
  if (text.startsWith('#!')) {
    while (i < text.length && !LINE_BREAK.test(text[i])) i += 1;
  }
  const last = () => tokens[tokens.length - 1];
  const regexAllowed = () => {
    const prev = last();
    if (prev === undefined) return true;
    if (prev.type === 'punct') return ![')', ']', '}', '++', '--'].includes(prev.value);
    if (prev.type === 'id') return REGEX_AFTER_WORDS.has(prev.value);
    return false;
  };
  const readString = (quote) => {
    let value = '';
    let escaped = false;
    i += 1;
    for (;;) {
      if (i >= text.length) fail('scan_unterminated');
      const ch = text[i];
      if (ch === '\\') {
        escaped = true;
        value += ch + (text[i + 1] ?? '');
        i += 2;
        continue;
      }
      if (ch === quote) {
        i += 1;
        return { type: 'string', value, escaped };
      }
      if (ch === '\n' || ch === '\r') fail('scan_unterminated');
      value += ch;
      i += 1;
    }
  };
  /** template本文を `${` か閉じ `\`` まで読む（本文は捨てる）。`${` なら式の文脈へ入る。 */
  const readTemplateText = () => {
    for (;;) {
      if (i >= text.length) fail('scan_unterminated');
      const ch = text[i];
      if (ch === '\\') {
        i += 2;
        continue;
      }
      if (ch === '`') {
        i += 1;
        tokens.push({ type: 'template' });
        return;
      }
      if (ch === '$' && text[i + 1] === '{') {
        i += 2;
        braces.push('template');
        tokens.push({ type: 'punct', value: '${' });
        return;
      }
      i += 1;
    }
  };
  const readRegex = () => {
    let inClass = false;
    i += 1;
    for (;;) {
      if (i >= text.length || LINE_BREAK.test(text[i])) fail('scan_unterminated');
      const ch = text[i];
      if (ch === '\\') {
        if (i + 1 >= text.length || LINE_BREAK.test(text[i + 1])) fail('scan_unterminated');
        i += 2;
        continue;
      }
      i += 1;
      if (ch === '[') inClass = true;
      else if (ch === ']') inClass = false;
      else if (ch === '/' && !inClass) break;
    }
    while (i < text.length && /[a-z]/i.test(text[i])) i += 1;
    tokens.push({ type: 'regex' });
  };
  while (i < text.length) {
    const ch = text[i];
    if (/\s/.test(ch) || ch === '﻿') {
      i += 1;
      continue;
    }
    if (ch === '/' && text[i + 1] === '/') {
      while (i < text.length && !LINE_BREAK.test(text[i])) i += 1;
      continue;
    }
    if (ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      if (end === -1) fail('scan_unterminated');
      i = end + 2;
      continue;
    }
    if (ch === '\'' || ch === '"') {
      tokens.push(readString(ch));
      continue;
    }
    if (ch === '`') {
      i += 1;
      readTemplateText();
      continue;
    }
    if (ch === '}' && braces[braces.length - 1] === 'template') {
      braces.pop();
      tokens.push({ type: 'punct', value: '}$' });
      readTemplateText();
      continue;
    }
    if (ch === '/') {
      if (regexAllowed()) {
        readRegex();
        continue;
      }
      if (text[i + 1] === '=') {
        tokens.push({ type: 'punct', value: '/=' });
        i += 2;
      } else {
        tokens.push({ type: 'punct', value: '/' });
        i += 1;
      }
      continue;
    }
    if (/[0-9]/.test(ch) || (ch === '.' && /[0-9]/.test(text[i + 1] ?? ''))) {
      i += 1;
      while (i < text.length && /[0-9A-Za-z_.]/.test(text[i])) {
        // 指数の符号（1e-5）だけを数値の一部として読む。
        if (/[eE]/.test(text[i]) && /[+-]/.test(text[i + 1] ?? '') && !/^0[xX]/.test(text.slice(i - 1))) i += 2;
        else i += 1;
      }
      tokens.push({ type: 'number' });
      continue;
    }
    if (ch === '#' || ID_START.test(ch)) {
      const start = i;
      i += 1;
      while (i < text.length && ID_PART.test(text[i])) i += 1;
      if (text[i] === '\\') fail('scan_invalid');
      tokens.push({ type: 'id', value: text.slice(start, i) });
      continue;
    }
    if (ch === '\\') fail('scan_invalid');
    const punct = PUNCTUATORS.find((item) => text.startsWith(item, i));
    if (punct === undefined) fail('scan_invalid');
    if (punct === '{') braces.push('brace');
    if (punct === '}') {
      if (braces.length === 0) fail('scan_invalid');
      braces.pop();
    }
    tokens.push({ type: 'punct', value: punct });
    i += punct.length;
  }
  if (braces.length !== 0) fail('scan_unterminated');
  return tokens;
}

const isPunct = (token, value) => token?.type === 'punct' && token.value === value;
const isId = (token, value) => token?.type === 'id' && (value === undefined || token.value === value);
const specifierOf = (token) => {
  if (token?.type !== 'string') return fail('scan_import_form');
  if (token.escaped || token.value.length === 0) return fail('scan_specifier_escape');
  return token.value;
};
/** 次の `from '<x>'` までの節（import・export節に現れてよいtokenだけ）を読み、specifierとその次の位置を返す。 */
function fromClause(tokens, start, code) {
  let depth = 0;
  for (let k = start; k < tokens.length; k += 1) {
    const token = tokens[k];
    if (depth === 0 && isId(token, 'from') && tokens[k + 1]?.type === 'string') return { specifier: specifierOf(tokens[k + 1]), next: k + 2 };
    if (isPunct(token, '{')) depth += 1;
    else if (isPunct(token, '}')) {
      if (depth === 0) fail(code);
      depth -= 1;
    } else if (!(isId(token) || isPunct(token, ',') || isPunct(token, '*') || (depth > 0 && token.type === 'string'))) fail(code);
  }
  return fail(code);
}

/**
 * ES moduleのtextから依存specifierを抽出する。戻り値 `{ imports, cjs }`（出現順・重複あり）。
 * 本文の値は評価せず、依存を判断できない形は `ModuleScanError` で拒否する。
 */
export function moduleSpecifiers(text) {
  const tokens = tokenize(text);
  const imports = [];
  const cjs = [];
  for (let k = 0; k < tokens.length; k += 1) {
    const token = tokens[k];
    if (token.type !== 'id') continue;
    const prev = tokens[k - 1];
    const next = tokens[k + 1];
    // property名（`a.import`・`a?.require`・`{ import: … }`）はkeywordではない。
    const member = isPunct(prev, '.') || isPunct(prev, '?.');
    const key = isPunct(next, ':') && (isPunct(prev, '{') || isPunct(prev, ','));
    if (member || key) continue;
    if (token.value === 'import') {
      if (isPunct(next, '(')) fail('scan_dynamic_import');
      if (isPunct(next, '.')) {
        if (!isId(tokens[k + 2], 'meta')) fail('scan_import_form');
        continue;
      }
      if (next?.type === 'string') {
        imports.push(specifierOf(next));
        k += 1;
        continue;
      }
      const clause = fromClause(tokens, k + 1, 'scan_import_form');
      imports.push(clause.specifier);
      k = clause.next - 1;
      continue;
    }
    if (token.value === 'export') {
      if (isPunct(next, '*')) {
        const clause = fromClause(tokens, k + 1, 'scan_export_form');
        imports.push(clause.specifier);
        k = clause.next - 1;
        continue;
      }
      if (isPunct(next, '{')) {
        let close = k + 1;
        while (close < tokens.length && !isPunct(tokens[close], '}')) {
          const inner = tokens[close];
          if (!(isPunct(inner, '{') || isPunct(inner, ',') || isId(inner) || inner.type === 'string')) fail('scan_export_form');
          close += 1;
        }
        if (close >= tokens.length) fail('scan_export_form');
        if (isId(tokens[close + 1], 'from')) {
          imports.push(specifierOf(tokens[close + 2]));
          k = close + 2;
        } else k = close;
      }
      continue;
    }
    if (token.value === 'require' && isPunct(next, '(')) fail('scan_require');
    if (token.value === 'requireCjs' && isPunct(next, '(')) {
      if (tokens[k + 2]?.type !== 'string' || !isPunct(tokens[k + 3], ')')) fail('scan_require_cjs_form');
      cjs.push(specifierOf(tokens[k + 2]));
      k += 3;
    }
  }
  return { imports, cjs };
}
