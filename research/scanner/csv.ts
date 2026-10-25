// Minimal RFC 4180 CSV reading and writing (no dependencies).

export function parseCsv(text: string): Record<string, string>[] {
  const src = text.replace(/^﻿/, '');
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;

  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (quoted) {
      if (c === '"' && src[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && src[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.some(f => f !== '')) rows.push(row);
      row = [];
    } else field += c;
  }
  row.push(field);
  if (row.some(f => f !== '')) rows.push(row);

  const [head, ...body] = rows;
  if (!head) return [];
  return body.map(r => Object.fromEntries(head.map((h, i) => [h.trim(), (r[i] ?? '').trim()])));
}

const cell = (v: unknown): string => {
  const s = v === null || v === undefined ? '' : typeof v === 'boolean' ? (v ? '1' : '0') : String(v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

/** CSV with a UTF-8 BOM so that Excel shows Turkish characters correctly. */
export function toCsv(rows: Record<string, unknown>[], columns: string[]): string {
  return '﻿' + [columns.join(','), ...rows.map(r => columns.map(c => cell(r[c])).join(','))].join('\r\n') + '\r\n';
}
