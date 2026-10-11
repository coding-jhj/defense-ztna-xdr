const PATTERNS = [
  { id: 'sqli-select-from', weight: 0.85, re: /\bselect\b[\s\S]{0,80}\bfrom\b/i },
  { id: 'sqli-tautology', weight: 0.9, re: /\bor\b\s*['"]?\s*\d+\s*['"]?\s*=\s*['"]?\s*\d+/i },
  { id: 'sqli-destructive', weight: 0.9, re: /;\s*(drop|delete|update|insert)\b/i },
  { id: 'sqli-weak-numeric-tautology', weight: 0.6, re: /\b(\d+)\s*=\s*\1\b/ },
  { id: 'sqli-comment-bypass', weight: 0.85, re: /'\s*(--|#)/ },
  { id: 'sqli-quote-tautology', weight: 0.85, re: /'\s*=\s*'/ },
  { id: 'sqli-union-comment-bypass', weight: 0.85, re: /union\s*(?:\/\*[\s\S]*?\*\/\s*)?select/i },
  { id: 'xss-script-tag', weight: 0.9, re: /<\s*script\b/i },
  { id: 'xss-event-handler', weight: 0.85, re: /\bon\w{2,20}\s*=/i },
  { id: 'xss-js-uri', weight: 0.8, re: /javascript:\s*\S/i },
  { id: 'xss-encoded-script-tag', weight: 0.85, re: /%3c\s*script/i },
  { id: 'path-traversal-repeated', weight: 0.85, re: /(\.\.[\\/]){3,}|(?:%2e%2e(?:%2f|%5c)){3,}/i },
];

export function decide(alert) {
  const text = String(
    alert?.description ??
      alert?.rule?.description ??
      alert?.desc ??
      alert?.message ??
      alert?.msg ??
      alert?.summary ??
      alert?.log ??
      ''
  );
  const matches = PATTERNS.filter((p) => p.re.test(text));

  if (matches.length === 0) {
    return { action: 'record', confidence: 0, reason: 'no-pattern-match' };
  }

  const base = Math.max(...matches.map((m) => m.weight));
  const bonus = Math.min((matches.length - 1) * 0.05, 0.1);
  const confidence = Math.round(Math.min(base + bonus, 0.99) * 100) / 100;

  let action;
  if (confidence >= 0.85) action = 'block';
  else if (confidence >= 0.5) action = 'alert';
  else action = 'record';

  return {
    action,
    confidence,
    reason: matches.map((m) => m.id).join('+'),
  };
}
