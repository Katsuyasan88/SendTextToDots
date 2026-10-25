// 公開HTTPS originの文字列検査（MCP/OAuthのissuer・resource・Web originの構成値に使う）。DNSへは問い合わせない。

const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * 正規化済みのhttps://DNS-host（ASCII小文字・2label以上・253字以下・user/pass/port/path/query/fragment/末尾slashなし）。
 * IP（最後のlabelが数字だけ）・localhost・*.localhostは拒否する。
 */
export function isDevelopmentPublicOrigin(value: unknown): value is string {
  if (typeof value !== 'string' || !value.startsWith('https://')) return false;
  const host = value.slice('https://'.length);
  if (host.length === 0 || host.length > 253) return false;
  const labels = host.split('.');
  if (labels.length < 2 || !labels.every((label) => DNS_LABEL.test(label))) return false;
  const last = labels[labels.length - 1] ?? '';
  if (/^[0-9]+$/.test(last) || last === 'localhost') return false;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  return parsed.origin === value && parsed.host === host && parsed.href === `${value}/`;
}
