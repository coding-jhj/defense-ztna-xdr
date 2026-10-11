import { readFile } from 'node:fs/promises';

const SECRET_LIKE = /\b(password|token|apikey|api_key|secret)=([^&\s]+)/gi;

function redactSecrets(text) {
  return text.replace(SECRET_LIKE, '$1=***');
}

export async function readAlerts(fixturePath) {
  const raw = await readFile(fixturePath, 'utf8');
  const alerts = JSON.parse(raw);

  return alerts.map((alert) => ({
    id: alert.id,
    time: alert.timestamp,
    srcAddr: alert?.data?.srcip ?? null,
    account: alert?.data?.user ?? null,
    ruleLevel: alert?.rule?.level ?? null,
    description: redactSecrets(String(alert?.rule?.description ?? '')),
  }));
}

export default readAlerts;
