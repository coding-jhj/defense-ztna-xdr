import path from 'node:path';
import { writeFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const moduleName = process.argv[2];

if (!moduleName) {
  console.error('사용법: npm run xdr:run -- <module-name>');
  process.exit(1);
}

const moduleDir = path.join(__dirname, moduleName);
const fixturePath = path.join(__dirname, 'fixtures', `${moduleName}.json`);

const { readAlerts } = await import(pathToFileURL(path.join(moduleDir, 'read-alerts.mjs')));
const { decide } = await import(pathToFileURL(path.join(moduleDir, 'decide.mjs')));
const { respond } = await import(pathToFileURL(path.join(moduleDir, 'respond.mjs')));

const alerts = await readAlerts(fixturePath);

const counts = { block: 0, alert: 0, record: 0 };
const decisions = [];

for (const alert of alerts) {
  const decision = decide(alert);
  counts[decision.action] += 1;
  await respond(alert, decision);
  decisions.push({
    alertId: alert.id,
    srcAddr: alert.srcAddr,
    action: decision.action,
    confidence: decision.confidence,
    reason: decision.reason,
  });
}

const result = {
  generatedAt: new Date().toISOString(),
  module: moduleName,
  totalAlerts: alerts.length,
  counts,
  decisions,
};

const resultPath = path.join(moduleDir, 'result.json');
await writeFile(resultPath, `${JSON.stringify(result, null, 2)}\n`);

console.log(`[${moduleName}] block=${counts.block} alert=${counts.alert} record=${counts.record} (총 ${alerts.length}건)`);
console.log(`결과 파일: ${resultPath}`);
