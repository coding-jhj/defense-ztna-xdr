import { readFile, writeFile, appendFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DENY_RULES_PATH = path.join(__dirname, '..', 'ztna', 'deny-rules.json');
const ALERTS_LOG_PATH = path.join(__dirname, '..', 'alerts.log');

const BLOCK_RULE_TTL_MS = 24 * 60 * 60 * 1000;

export async function respond(alert, decision) {
  const now = new Date();

  if (decision.action === 'block') {
    const rulesFile = JSON.parse(await readFile(DENY_RULES_PATH, 'utf8'));
    // 같은 경보로 이미 만든 규칙은 최신 판정으로 교체해, 다시 실행해도 규칙이 중복 누적되지 않게 함
    rulesFile.rules = rulesFile.rules.filter((rule) => rule.basedOnAlertId !== alert.id);
    rulesFile.rules.push({
      id: `deny-${alert.id}`,
      srcAddr: alert.srcAddr,
      reason: decision.reason,
      basedOnAlertId: alert.id,
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + BLOCK_RULE_TTL_MS).toISOString(),
    });
    await writeFile(DENY_RULES_PATH, `${JSON.stringify(rulesFile, null, 2)}\n`);
  }

  if (decision.action === 'block' || decision.action === 'alert') {
    const line = `${now.toISOString()} [${decision.action.toUpperCase()}] alert=${alert.id} srcAddr=${alert.srcAddr} confidence=${decision.confidence} reason=${decision.reason}\n`;
    await appendFile(ALERTS_LOG_PATH, line);
  }
}

export default respond;
