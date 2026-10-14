# CHANGES — sec-scan-auth v1 → v2

작업 위치: `D:\100. ㅊㅇㅇ\sec-scan-auth_v2\` (임시 경로)
palantir 레포 반영: **안 함** — 사용자 확인 후 승인 시에만 복사 (아래 「반영 방법」)
작성일: 2026-10-14

---

## 1. 한 줄 요약

`/sec-scan-auth` 진입점 하나는 그대로 두고, 내부를 **M0(구조 파악) + M1~M5(모듈)** 로 나눴다. 원본 MD 5종의 내용을 원문 보존본과 모듈 판정 기준으로 빠짐없이 반영했다.
출력 파일, category 9종, `AUTH-` ID 체계, `/sec-review` 연계는 v1과 같다.

## 2. 검증 결과

| 검증 | 결과 | 보고서 |
|---|---|---|
| 원본 MD 라인 누락 (`verify_coverage.py`) | 1,532라인 검사, 누락 0, 식별정보 잔존 0 — PASS | `_review/coverage_report.txt` |
| 구조 정합성 (`verify_structure.py` S1~S11) | 오류 0 — PASS (경로 30, 판정 문구 58, 교차 참조 74, `--skip` 값, summary 섹션, 스키마 신규 오류 0) | `_review/structure_report.txt` |
| v1 라인 대응 (S10) | SKILL 26 / task_26 77 / commands 4라인 전부 이동·보강·정정·대체로 분류, 삭제 0 | `_review/COVERAGE_MATRIX.md` Part 2 |

재실행:
```bash
cd /c/Users/skplanet
py -3 -I "/d/100. ㅊㅇㅇ/sec-scan-auth_v2/_review/tools/verify_coverage.py"  "D:/100. ㅊㅇㅇ/sec-scan-auth_v2"
py -3 -I "/d/100. ㅊㅇㅇ/sec-scan-auth_v2/_review/tools/verify_structure.py" "D:/100. ㅊㅇㅇ/sec-scan-auth_v2" "D:/5. Skills/MySkills/palantir-main (1)/palantir-main"
```

## 3. 파일 변경 목록

### 수정 (palantir 레포에 이미 있는 파일 — 반영 시 덮어씀)
| 파일 | 변경 |
|---|---|
| `sec-scan-auth/SKILL.md` | 오케스트레이터로 재작성: 모듈 표, `--only` 인자, 3단 references 로드, Phase 2 = M0, repo 유형 분기(mobile-client → M5만), 모듈 ↔ `--skip` 매핑, 모듈 순차 LLM-Check, summary 섹션 4개 추가, 게이트 검사 3개 추가, Step 5 완료 후 대기 |
| `sec-scan-auth/references/task_prompts/task_26_auth_review.md` | 공통 규칙 허브로 재작성: 모듈 목록, v1 섹션 대응표, RULE-1~4 보강, RULE-5(verification_status·DAST)·RULE-6(심각도 조정 근거) 신규, 모듈 간 병합 규칙, 판정 기준 확장, 출력 필드 `source_module`/`verification_status` 추가, task_25 경로 정정 |
| `.claude/commands/sec-scan-auth.md` | `argument-hint` 추가, M0 읽기 단계 추가, 실행 순서 갱신, 완료 후 대기 |

### 신규
| 파일 | 내용 |
|---|---|
| `sec-scan-auth/references/modules/m0_auth_recon.md` | repo 유형 판별, 스택, 인증 메커니즘 위치, 흐름 플래그, 민감 엔드포인트, `module_plan`, `auth_map.json` 스키마 (판정 없음) |
| `sec-scan-auth/references/modules/m1_authn.md` | A-1 / A-2 / A-6 + 판정 요약표 |
| `sec-scan-auth/references/modules/m2_authz_acl.md` | A-3 / A-5 / B-1 ~ B-4 + 판정 요약표 |
| `sec-scan-auth/references/modules/m3_stepup_mfa.md` | C-1 PIN 재검증, C-2 2차 인증 코드 신호, C-3 M4 이관 + 판정 요약표 |
| `sec-scan-auth/references/modules/m4_logic_race.md` | D-1 ~ D-9 (P1~P9) + 판정 요약표 |
| `sec-scan-auth/references/modules/m5_webview_client.md` | E-0 ~ E-6 + 판정 요약표 |
| `sec-scan-auth/references/dast_candidates.md` | `dast_candidates_AUTH.json` 형식 (축소 방식) |
| `sec-scan-auth/references/methodology/auth_methodology.md` | 원본 AUTH + AUTHP5 원문 보존 (익명화) |
| `sec-scan-auth/references/methodology/acl_methodology.md` | 원본 ACL + AUTH Step 3 / 사례 A-05~A-07 |
| `sec-scan-auth/references/methodology/race_condition_methodology.md` | 원본 RACE + AUTH Step 8 / 사례 A-03 |
| `sec-scan-auth/references/methodology/webview_session_methodology.md` | 원본 WEBVIEW |
| `sec-scan-auth/references/methodology/intentional_exclusions.md` | 의도적 제외 목록 (표 A 라인 단위 — verify_coverage가 읽음 / 표 B 판정 범위 축소 + 결정 ID) |

### 수정하지 않음
- `shared/` 전체 (`vuln_taxonomy.md`, `output_schemas.md`, `scan_auth_access_control.py`, `validate_findings.py` 등)
- `tools/approve_report.py`, 다른 `sec-scan-*` skill

### 새로 생기는 실행 산출물 (진단 시 `state/<prefix>/`)
| 파일 | 비고 |
|---|---|
| `auth_map.json` | M0 출력, 같은 prefix면 재사용 |
| `dast_candidates_AUTH.json` | 진단자 참고용. 업로드·`/sec-review`·최종 보고서에 연결하지 않음 |

## 4. 사용자 결정 반영

| 결정 | 내용 | 반영 |
|---|---|---|
| 1번 a | DAST 후보는 별도 파일, 공유 스키마/approve_report.py 미수정 | `dast_candidates_AUTH.json` |
| 2번 | 실제 사례는 익명화해서 포함 | methodology Part C, 식별정보 잔존 검사 0 |
| 3번 | Spring Boot/Kotlin 유지 | 모듈 grep |
| 구조 | 하나의 진입점 + 모듈 분리, 기존 틀 유지 | SKILL.md / modules |
| M3 1-a | 2차 인증·문자 인증은 코드 신호만 기록 (판정·테스트 절차·finding 없음) | M3 C-2 |
| DAST 2 | 축소 방식: 코드 신호 / 정적 확정 불가 사유 / 관련 finding만 | `dast_candidates.md` §3 작성 금지 목록 |
| validator | `validate_findings.py`의 auth 미지원 문제는 이번 작업과 분리 | §7 F-2 (별도 과제) |

---

## 5. 반영 전 검토 포인트 (사용자 확인 필요)

### R-1. 완료 후 동작 문구 변경
- v1 SKILL.md L225: "Phase C-1 완료 후 `/sec-review` 로 인터랙티브 정/오탐 판정을 진행한다."
- v2 Step 5: 완료 요약을 출력하고 **대기**한다. `/sec-review` 자동 실행 금지.
- 근거: CLAUDE.md BOUNDARY RULE ("`/sec-scan-*` 완료 후 `/sec-review` 자동 실행" 금지). v1 문구는 자동 이행으로 읽힐 여지가 있었다.

### R-2. 심각도 — taxonomy 기본값과 다른 지정
taxonomy Section 6 기본값과 다르게 지정한 항목이다. 모두 RULE-6에 따라 사유를 `manual_review_note`에 남기도록 했다.

| 위치 | 항목 | 기본값 | v2 지정 | 근거 |
|---|---|---|---|---|
| M2 A-3 | 배치 API 무인증 — 캐시 재구성 등 가용성 영향만 | Critical | Medium | 원본 사례 A-04 "중간" |
| M2 A-3 | 배치 API 무인증 — 금전 외 데이터 변경·외부 발송 | Critical | High | 이번 지정 (A-04와 Critical 사이 구간) |
| M2 B-2 | ACL 환경 우회 — 외부 노출 근거 없음 | High | Medium | 원본 사례 A-07 "낮음(환경 의존)" + v1 판정 기준 "외부 비접근 서버 Medium" |
| M2 B-3 | IP ACL — 영향 제한적 | High | Medium | 원본 사례 A-05/A-06 "중간" |
| M2 B-3 | XFF — 프록시 존재 불명 | High | Medium | 원본 최종 판단 요약 "프록시 환경 → 중간" |
| M3 C-1 | PIN 누락 — 금전 이동 없는 정보변경 / 유효시간 과다 | High | Medium | 이번 지정 |
| M4 D-3 | P2 — 금전 외 | Medium~High | Medium | 원본 P2 "중간~높음"을 금전 여부로 구분 (이번 지정) |
| M1 A-6 | Gateway 내부 헤더 외부 덮어쓰기 가능 | AUTH_BYPASS Critical | Critical | 기본값과 같음 (항목 자체는 원본 근거) |
| M5 E-1 | 외부 저장소 토큰 | SESSION_TOKEN_EXPOSURE Medium | High | 이번 지정 |
| M5 E-1 / E-2 | 로그아웃 시 토큰·Webview 세션 미삭제 | Medium | Low | 이번 지정 |
| M5 E-2 | 임의 URL로 헤더 주입 / 도메인 제한 없는 JS Bridge / `postMessage(..., '*')` | Medium | High | 이번 지정 |
| M5 E-3 | 전역 cleartext + http 토큰 전달 / SSL 오류 무시 | Medium | High | 이번 지정 |
| M5 E-0 | 세션 ID 예측 가능 | Medium | High | 이번 지정 |
| M5 E-5 | 앱 고정 토큰·인증 생략 | Medium | High | 이번 지정 |

### R-3. 원본에 직접 근거가 없는 추가 판정 기준
원본 MD에 해당 기술 항목이 없거나, 원본은 확인 항목만 제시하고 판정 기준은 이번에 정한 것이다. 반영하지 않으려면 해당 줄만 지우면 된다 (다른 절과 의존 관계 없음).

| 위치 | 추가 기준 | 원본과의 관계 |
|---|---|---|
| M1 A-6 | 외부 인증 서버 호출 URL에 요청 값 반영 → AUTH_BYPASS **정보** (SSRF 가능성) | 원본에 SSRF 위험 언급 있음. taxonomy에 SSRF category가 없어 정보 등급으로 둔 것은 이번 결정 |
| M1 A-6 | 쿠키 `Secure`/`HttpOnly`/`SameSite` 미설정 → SESSION_TOKEN_EXPOSURE Medium | 원본은 확인 항목, 판정은 이번 지정 |
| M2 B-2 | regEx `find()`/`containsMatchIn()` 부분 일치 → IP_ACL_BYPASS High | 원본은 regEx 속성 확인만, 부분/전체 일치 판정은 이번 추가 |
| M3 C-1 | PIN 확인 필드를 요청 값으로 채우면 검사가 있어도 취약 | 이번 추가 |
| M4 D-2 | self-invocation / `private` 메서드 `@Transactional` 미적용 → P1 | 이번 추가 (Spring 프록시 동작) |
| M4 D-4 | `PESSIMISTIC_READ`는 쓰기 구조의 동시 읽기를 막지 못함 | 원본은 grep 대상으로만 포함, 판정은 이번 추가 |
| M4 D-6 | `@Scheduled` 다중 인스턴스 (ShedLock 등 부재) → needs-dynamic-verification | 이번 추가 |
| M4 D-6 | Redis get/set 분리 → P6 취약, 원자적 선점(SETNX/tryLock)이면 양호 | 원본 "get→check→set 순서" 확인 항목을 원자성 기준으로 구체화 |
| M4 D-1 | 상태 변경 GET은 finding 없이 note, CSRF 사실은 M2로 | 원본은 탐지 항목만, 처리 방식은 이번 결정 |
| M5 E-2 | 로드 URL 제한을 `contains()`/prefix로 하면 "제한 없음"과 동일 | 이번 추가 (M2 contains 판정과 같은 논리) |
| M5 E-3 | `onReceivedSslError` → `proceed()`, ATS 해제, cleartext 판정 | 원본 "HTTPS 강제 여부" 확인 항목을 구체화 |
| M5 E-5 | `setWebContentsDebuggingEnabled(true)` 비게이팅 → Medium | 이번 추가 |
| M5 E-1 | Android `DataStore`, RN `EncryptedStorage`, Flutter `shared_preferences` 탐색 | 원본 저장소 표에 없는 라이브러리 추가 |

### R-4. 출력 필드 추가
- finding: `source_module`, `verification_status` / `findings_AUTH.json` summary: `needs_dynamic_verification` / `scan_coverage`: `modules_run`, `modules_skipped`
- `auth_map.json` (신규 파일): `source`, `source_ref.repo_commit` / `source_hash` / `scope` (R-6 #3, #5)
- `auth_access_assessment`: `auth_map_path`, `modules_run`, `modules_skipped`, `pin_candidates_*`, `stepup_signals[]`, `m4_handoff[]`, `dast_candidates_count`
- `validate_findings.py`는 추가 필드를 거부하지 않음 (S9: v1 대비 신규 오류 0). `tools/approve_report.py` / `tools/generate_final_report.py`와 `shared/scripts/`에 이 필드명을 참조하는 코드가 없으므로 (grep 확인) 보고서 출력은 v1과 같다.

### R-5. 토큰 사용량
- 모듈 파일은 `module_plan`에서 실행하는 것만 읽고, methodology(4개 2,638줄)는 판정이 애매할 때 해당 절만 부분 로드한다.
- 그래도 전 모듈 실행 시 읽는 지침 양은 v1(task_26 503줄)보다 많다 (task_26 376줄 + 모듈 6개 1,012줄 = 1,388줄). 실제 repo로 1회 시험 실행해 보고 조정하는 것을 권장한다.

---

### R-6. 외부 검토 의견 반영 (2026-10-14)

claude web 검토 의견 6건과 추가 질문 1건의 처리 결과다.

| # | 의견 | 처리 | 위치 |
|---|---|---|---|
| 1 | DAST 후보에 재현 입력값(재현 시나리오) 추가 | **반영 안 함 — 결정 D-2 유지**. 근거는 아래 | `dast_candidates.md` §3, `intentional_exclusions.md` 표 B |
| 2 | M2 IDOR에 "검증이 있어도 동적에서만 확인되는 경우" 축 추가 | **부분 반영**: 소유권 검증 상태 3분류(없음 / 간접 / 직접), 간접 검증은 `needs-dynamic-verification` + DAST 후보. 후보에는 객체 참조 파라미터·검증 위치·작업 유형 등 코드 신호만 기록. 계정 조합 등 테스트 설계는 넣지 않음 (D-2) | M2 A-5 [v2 추가] |
| 3 | `auth_map.json`에 출처 필드 | **반영**: `source` (`static-code` 사용, `openapi-spec`/`behavioral-observed`/`mixed`는 예약), 비코드 출처 맵일 때 판정 규칙 | M0 스키마 |
| 4 | 커버리지에 "의도적 제외" 개념 | **반영**: `intentional_exclusions.md` 표 A를 `verify_coverage.py`가 읽음. 생성기 제외 목록과 불일치 시 FAIL (음성 테스트로 확인) | `methodology/intentional_exclusions.md`, `tools/verify_coverage.py` |
| 5 | `auth_map.json` 재사용 시 stale 방지 | **반영**: `source_ref.repo_commit` / `source_hash` / `scope` 기록, 일치할 때만 재사용 | M0 R-7, SKILL.md `--only` |
| 6 | validator(F-2)를 반영 선행 과제로 | **반영**: §8 반영 절차에 F-2 선행 의존성 명시 | §7 F-2, §8 |
| 질문 | M4 P1~P9가 언제 DAST 후보가 되는지 | **반영**: 패턴별 `code-confirmed` / `needs-dynamic-verification` / 양호 조건 표. P5·P7은 항상 정적 확정 | M4 D-8 |

**의견 1을 반영하지 않은 근거**
- 결정 D-2(2026-10-13)는 DAST 후보 파일을 "진단자가 동적 진단 대상을 고르는 참고 목록"으로 한정했다. 테스트 절차·재현 입력값·성공 판정 기준은 진단자가 정한다.
- 재현 입력값은 판정을 빼더라도 실행 가능한 테스트 설계에 해당한다. 정적 분석 skill의 산출물 범위(코드 근거 기록)를 넘는다.
- 이 skill의 산출물은 고객사 소스 진단 결과와 함께 보관·전달된다. 실행 가능한 테스트 입력을 자동 생성해 남기는 것은 별도 검토(사용 범위, 승인 절차)가 필요하다.
- 나중에 동적 검증 skill을 붙일 경우, 그 skill이 `dast_candidates_AUTH.json`의 대상·코드 신호·`why_not_static`을 입력으로 받아 자체 절차를 정하는 구조가 가능하다. 이 skill 쪽 형식은 바꿀 필요가 없다.
- 이 결정을 바꾸려면 D-2를 재결정하고 `intentional_exclusions.md` 표 B 해당 행을 갱신한다.

## 6. 알려진 한계

- **실제 repo 실행 검증 안 함**: 이번 검증은 문서 정합성과 원문 커버리지까지다. M0 `module_plan` 판정, 모듈별 grep의 오탐·누락은 실제 진단 1회로 확인해야 한다.
- M5 grep은 `--include` 위주라 Swift/Dart/RN 프로젝트 구조에 따라 경로 조정이 필요할 수 있다.
- M3 C-2와 DAST 후보는 사용자 결정에 따라 판정을 하지 않는다. 2차 인증 우회 여부는 진단자가 판단한다.

## 7. 검증 중 발견·처리한 문제

### F-1. task_26의 task_25 참조 경로 오류 (v1부터) — 정정함
- v1 L358: `shared/references/task_prompts/task_25_data_protection.md` → 실제 파일 없음
- v2: `sec-scan-data/references/task_prompts/task_25_data_protection.md`

### F-2. `validate_findings.py`가 auth 결과를 거부 (v1부터) — **분리, 별도 과제**
- 현황: `FINDING_ID_RE`가 `INJ|XSS|FILE|DATA|SCA`만, `VALID_CATEGORY`에 auth 9종 없음 → v1/v2 모두 `findings_AUTH.json`이 `finding_id 형식 오류`, `category 비표준값` 2종 오류로 실패
- 이번 작업 범위 밖(`shared/` 수정 안 함). 사용자 결정으로 분리.
- **palantir 반영의 선행 과제** (2026-10-14 검토 반영): v2를 반영하기 전에 F-2를 먼저 처리해야 한다. 그렇지 않으면 반영 후 `findings_AUTH.json` 검증 단계가 실패한다 (v1도 같은 상태였음).
- 별도로 처리할 때 필요한 변경: `SKILL_PREFIXES`·`FINDING_ID_RE`에 `AUTH` 추가, `VALID_CATEGORY`에 taxonomy Section 6의 9종 추가. 처리 후 `verify_structure.py` S9의 「기존 갭」 2건이 사라지면 된다.

### F-3. Windows 인코딩
- v1 게이트 스크립트의 `read_text()`는 cp949 기본 인코딩에서 한글 JSON을 읽다 실패할 수 있어 `encoding='utf-8'`로 정정 (SKILL.md Step 4-1).
- 참고: `validate_findings.py`도 cp949 콘솔에서 ✅/❌ 출력 시 `UnicodeEncodeError`가 난다 (`-X utf8` 또는 `PYTHONIOENCODING=utf-8`로 회피). F-2와 같은 별도 과제로 묶는 것을 권장.

---

## 8. 반영 방법 (승인 시)

**선행 조건 (반영 전에 끝나 있어야 함)**
1. F-2 `validate_findings.py` auth 지원 — 별도 과제로 먼저 처리하고, `verify_structure.py` S9의 「기존 갭」 0건 확인
2. R-2 / R-3 / R-6 검토 완료

반영 대상 (staging → palantir 레포, 같은 상대 경로):
```
sec-scan-auth/SKILL.md
sec-scan-auth/references/task_prompts/task_26_auth_review.md
sec-scan-auth/references/dast_candidates.md
sec-scan-auth/references/modules/*.md          (6개)
sec-scan-auth/references/methodology/*.md      (5개 — intentional_exclusions.md 포함)
.claude/commands/sec-scan-auth.md
```
- `_review/` 폴더는 반영하지 않는다 (검토용).
- 반영 전 레포 쪽 3개 파일이 백업(`_review/original/`)과 md5가 같은지 확인한다 (그 사이 다른 변경이 없었는지).
- 반영 후 `verify_structure.py`를 레포 경로 기준으로 한 번 더 실행한다.
- 커밋 여부는 별도로 확인한다.
