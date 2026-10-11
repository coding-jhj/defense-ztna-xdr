# AGENTS.md

이 저장소는 ZTNA(제로 트러스트 네트워크 접근) 판정기와, 그 판정기에 탐지 결과를 넘겨주는 XDR 탐지 모듈들을 담습니다.

## 판정기 규칙 파일
- 거부(차단) 규칙 저장소: `xdr/ztna/deny-rules.json`
- 이 파일은 각 탐지 모듈의 `respond.mjs`가 "차단(block)" 판정을 받은 경보에 대해서만 규칙을 추가합니다.
- 규칙마다 만료 시각(`expiresAt`, 생성 후 24시간)과 근거 경보 번호(`basedOnAlertId`)를 반드시 포함합니다.
- 정상 사용자를 막는 규칙은 추가되지 않습니다 — `decide.mjs`가 패턴 매칭으로 "공격"이라고 확신한(신뢰도 0.85 이상) 경보만 차단 후보가 됩니다.

## 탐지 모듈 구조 (`xdr/<module-name>/`)
각 탐지 모듈은 역할이 분리된 4개 파일로 구성됩니다.
- `read-alerts.mjs`: 원본 경보를 읽기만 하는 모듈. 시각·출발 주소·계정·규칙 수준·설명만 추출하고, 비밀값처럼 보이는 값(`password=`, `token=` 등)은 출력 전에 `***`로 가립니다. 원본 fixture 파일은 수정하지 않습니다.
- `patterns.json`: 탐지 패턴과 그 근거를 적어두는 사람이 읽는 문서.
- `decide.mjs`: `patterns.json`의 내용을 상수로 복사해 두고, 경보 하나를 받아 판정 하나(`{action, confidence, reason}`)를 돌려주는 순수 함수. **import 문이 없고, 파일을 읽거나 쓰지 않으며, 외부에 묻지 않고 혼자 계산합니다.**
- `respond.mjs`: `decide.mjs`의 판정 결과를 받아 차단 규칙 생성(`xdr/ztna/deny-rules.json`)과 알림 기록(`xdr/alerts.log`)을 담당합니다. `decide.mjs`는 이 파일을 모르고, 이 파일도 `decide.mjs`의 판단 로직을 바꾸지 않습니다.

## 실행
`npm run xdr:run -- <module-name>` 으로 한 모듈을 전체 실행하고, `xdr/<module-name>/result.json`에 집계 결과를 남깁니다. 실행 순서는 `xdr/run.mjs`가 담당합니다 (경보 읽기 → 판정 → 대응, 세 단계를 연결만 함).

## 현재 모듈
- `xdr/web-injection/`: SQL 인젝션 · XSS · 경로 조작(`../` 반복) 탐지.
  - 근거: MITRE ATT&CK T1190 (Exploit Public-Facing Application), CISA AA23-158A (Cl0p / MOVEit Transfer SQL 인젝션, CVE-2023-34362)
  - 패턴 근거는 `xdr/web-injection/patterns.json`에 패턴마다 한 줄씩 기술
