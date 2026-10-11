# defense-ztna-xdr

ZTNA(제로 트러스트 네트워크 접근) 판정기와, 웹 주입 공격을 탐지해 판정기에 차단 규칙을 넘겨주는 XDR 탐지 모듈 실습 프로젝트입니다.

## 배경: 왜 이 모듈을 만드는가

2023년 Cl0p 랜섬웨어 조직은 파일 전송 소프트웨어 **MOVEit Transfer**의 제로데이 SQL 인젝션 취약점(**CVE-2023-34362**)을 악용해 **LEMURLOOT** 웹셸을 심고, 전 세계 수많은 기관의 데이터베이스에서 대량으로 데이터를 빼냈습니다. ([CISA AA23-158A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a))

CISA는 이 사고를 "웹 요청에 섞인 SQL 구문을 걸러내고, 비정상 쿼리·새로 생긴 웹 파일을 탐지했다면 더 일찍 막을 수 있었다"고 분석합니다. 이 저장소의 `xdr/web-injection` 모듈은 바로 그 지점 — **외부 공개 애플리케이션 악용 (MITRE ATT&CK [T1190](https://attack.mitre.org/techniques/T1190/))** — 을 겨냥한 탐지기입니다.

## 폴더 구조

```
xdr/
  fixtures/web-injection.json   # 테스트용 Wazuh 스타일 경보 11건 (정상 5 / 공격 5 / 애매 1)
  ztna/deny-rules.json          # ZTNA 판정기의 거부 규칙 저장소 (respond.mjs가 씀)
  alerts.log                    # block·alert 등급 알림 로그 (실행 시 생성)
  run.mjs                       # read-alerts → decide → respond 를 연결하는 실행기
  web-injection/
    read-alerts.mjs             # 경보 읽기 전용 (비밀값 마스킹)
    patterns.json               # 탐지 패턴 + 근거 (사람이 읽는 문서)
    decide.mjs                  # 패턴 매칭 → block/alert/record 판정 (외부 의존성 없는 순수 함수)
    respond.mjs                 # 차단 규칙 생성 + 알림 기록
    result.json                 # 실행 결과 집계 (실행 시 생성)
```

역할 분리 원칙은 `AGENTS.md`에 자세히 적어두었습니다.

## 실행 방법

```bash
npm run xdr:run -- web-injection
```

`xdr/web-injection/result.json`에 전체 집계가, `xdr/alerts.log`에 알림 로그가, `xdr/ztna/deny-rules.json`에 차단 규칙이 쌓입니다.

## 탐지 로직

`xdr/web-injection/patterns.json`에 정의된 8개 패턴(SQL 인젝션 4종, XSS 3종, 경로 조작 1종)을 경보 설명 문구에 매칭합니다. 매칭된 패턴 중 가장 높은 가중치를 기본 신뢰도로 삼고, 여러 패턴이 동시에 맞으면 소폭 가산합니다.

| 신뢰도(confidence) | 판정(action) |
|---|---|
| 0.85 이상 | `block` — ZTNA 판정기에 차단 규칙 등록 |
| 0.5 이상 0.85 미만 | `alert` — 차단하지 않고 로그만 남겨 사람이 확인 |
| 0.5 미만 (패턴 미일치 포함) | `record` — 조용히 집계만 함 |

## 검증 결과

고정 테스트 데이터(`xdr/fixtures/web-injection.json`) 11건으로 실행한 결과:

- **공격 5건 전부 `block`**: SQL UNION 삽입, SQL 항진명제(`OR '1'='1'`), XSS `<script>` 태그, `../` 6회 반복 경로 조작, SQL 파괴 구문(`; DROP TABLE`)
- **애매한 1건은 `alert`**: 따옴표 없는 숫자 항진명제(`1=1`)만 단독으로 매칭된 경우 — 차단 대신 사람이 확인하도록 남김
- **정상 이벤트 5건은 전부 `record`, 오탐 0건**: 로그인(`user=...&password=...`), `select your favorite color`(SQL 키워드지만 구조 아님), `subscription_script_v2.pdf`(script라는 글자만 포함), `../images/logo.png`(상대경로 1회만)처럼 **의도적으로 오탐을 유발하기 쉬운 정상 트래픽**을 섞어 넣고도 전부 정상 처리됨을 확인했습니다.

전체 결과는 `xdr/web-injection/result.json`에서 확인할 수 있습니다.
