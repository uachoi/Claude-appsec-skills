# 의도적 제외 목록 (intentional exclusions)

원본 MD 내용 중 **의도적으로** v2에 넣지 않았거나 판정 범위를 줄인 항목이다.
`_review/tools/verify_coverage.py`는 표 A의 라인을 "누락"이 아닌 "제외(사유 기재)"로 처리한다. 표 A에 없는 원본 라인이 결과물에 없으면 누락(FAIL)이다.

판정 기준을 조정하면서 원본 내용을 빼야 할 때는 **먼저 이 파일에 행을 추가**하고, 그다음 내용을 지운다.

---

## 표 A. 원문 라인 단위 제외 (verify_coverage.py가 읽음)

열 형식은 고정이다: `원본키 | 시작라인 | 끝라인 | 사유 | 결정 ID`

| 원본키 | 시작라인 | 끝라인 | 사유 | 결정 ID |
|---|---|---|---|---|
| AUTH | 9 | 16 | 목차(TOC) — 재구성된 파일 구조로 대체 | D-STRUCT |
| RACE | 9 | 16 | 목차(TOC) — 재구성된 파일 구조로 대체 | D-STRUCT |

원본키: `AUTH`(4. AUTH(DAST)_VULN_ANALYSIS.md) · `AUTHP5`(Auth_Analysis.md) · `ACL`(ACL_Analysis.md) · `RACE`(6. RACE_CONDITION_ANALYSIS.md) · `WEBVIEW`(WEBVIEW_SESSION_ANALYSIS.md)

---

## 표 B. 판정·출력 범위 제외 (원문은 보존, 실행 지침에서만 범위를 줄임)

원문은 `methodology/`에 그대로 남아 있으므로 라인 검증에는 영향이 없다. 결정의 근거 추적용이다.

| 대상 | 제외·축소 내용 | 결정 ID | 반영 위치 |
|---|---|---|---|
| 2차 인증·문자 인증 | 우회 판정, finding 생성, 테스트 절차 — 코드 신호 기록만 | D-1a | M3 C-2 |
| 동적 확인 후보 | 테스트 절차·요청 예시·재현 입력값·성공 판정 기준 — 코드 신호 / 정적 확정 불가 사유 / 관련 finding만 | D-2 | `dast_candidates.md` §3 |
| 원본 6.3 취약점 발견 목록 (상/중/하) | 별도 표 대신 findings + 「모듈별 판정 요약」, severity로 대체 | D-STRUCT | M5 E-6 |
| 원본 2.2 분석 도구 준비 | 실행 지침에 넣지 않음 (도구 설치 안내) | D-STRUCT | — |
| 하드코딩 값·로그 노출·Webview XSS | 판정하지 않고 다른 skill로 경계 메모 | D-BOUND | M1 / M5 경계 |
| 인증서 피닝 부재 | finding 없음, 기록만 (원본도 확인 항목으로만 제시) | D-STRUCT | M5 E-3 |

## 결정 ID

| ID | 내용 | 일자 |
|---|---|---|
| D-1a | M3 2차 인증·문자 인증은 코드 신호만 기록 | 2026-10-13 |
| D-2 | DAST 후보 축소 방식 (재검토 2026-10-14 — 유지, CHANGES R-6) | 2026-10-13 |
| D-STRUCT | 모듈 구조 개편에 따른 재배치 | 2026-10-13 |
| D-BOUND | 다른 skill 경계 (sec-scan-data / sec-scan-xss) | 2026-10-13 |
