# COVERAGE_MATRIX — sec-scan-auth v2

원본 MD 5종(7개 파일, md5 동일 중복 2쌍)과 v1 skill 3개 파일이 v2 어디에 반영되었는지 정리한다.

- **원문 보존**: `sec-scan-auth/references/methodology/*.md` — 원본 전 라인 복사 + 익명화 (기계 검증: `coverage_report.txt` 1,532라인 누락 0)
- **실행 반영**: `sec-scan-auth/references/modules/m0~m5`, `task_26_auth_review.md`, `SKILL.md`, `dast_candidates.md` — LLM이 실제로 따르는 절차·판정 기준
- **구조 정합성**: `structure_report.txt` (S1~S11 오류 0)

표기: ✅ 판정 기준까지 반영 · 📝 기록 항목으로 반영(판정 없음) · ↗ 다른 skill 경계(메모만) · 📎 원문 보존본에만 존재(참조용)

---

## Part 1. 원본 MD → v2 반영 위치

### 1-1. AUTH — `4. AUTH(DAST)_VULN_ANALYSIS.md` (= `MySkills/5. AUTH_VULN_ANALYSIS.md`, 712줄)

| 원본 절 | 원본 라인 | 원문 보존 | 실행 반영 | 상태 |
|---|---|---|---|---|
| 개요·핵심 원칙 | L1-7, L20-36 | auth_methodology Part B | M0 역할 정의 | 📎 |
| Step 1 커스텀 어노테이션/AOP 전수 조사 | L40-166 내 | auth_methodology Part B | M0 R-3 (위치), M1 A-1 [추가] 처리기 차단 로직 확인 | ✅ |
| Step 2-1 어노테이션 선언 / 기본값 | L40-166 내 | auth_methodology Part B | M1 A-2 [추가] `required` 기본값 표 | ✅ |
| Step 2-2 결제·민감 API required=false | L40-166 내 | 〃 | M1 A-2 판정 | ✅ |
| Step 2-3 AOP Pointcut 범위 | L40-166 내 | 〃 | M1 A-1 판정 | ✅ |
| Step 2-4 테스트 세션 우회 | L40-166 내 | 〃 | M1 A-2 판정 | ✅ |
| Step 2-5 인증 서버 타임아웃 | L40-166 내 | 〃 | M1 A-2 [추가] Fail-Open 판정표 | ✅ |
| Step 3 @Acl AOP 구현 (3-1~3-3) | L168-247 | acl_methodology Part B | M2 B-2 / B-3 | ✅ |
| Step 4 배치/관리 API 무인증 | L249-353 내 | auth_methodology Part B | M2 A-3 | ✅ |
| Step 5 PIN/비밀번호 서버 검증 (5-1~5-3) | L249-353 내 | auth_methodology Part B | M3 C-1 | ✅ |
| Step 6 IDOR | L249-353 내 | auth_methodology Part B | M2 A-5 | ✅ |
| Step 7 하드코딩 인증 정보 | L249-353 내 | auth_methodology Part B | M1 경계 규칙 (sec-scan-data `HARDCODED_SECRET`), 입력 무시·고정값 대체 흐름은 M3 C-1 | ↗ / ✅ |
| Step 8 Race Condition (TOCTOU) | L355-385 | race_condition_methodology Part B | M4 D-2 [추가] Controller 분리 호출, D-4 사례 A-03 핵심 결함, `readOnly` | ✅ |
| Step 9 세션/토큰 전달 아키텍처 | L387-436 | auth_methodology Part B | M1 A-6 [추가] 아키텍처 유형 분류 표, M5 실행 트리거 | ✅ |
| 발견 취약점 목록 A-01~A-07 | L440-454 | auth_methodology Part C | 각 모듈 심각도 조정 근거 (RULE-6) | ✅ |
| 사례 A-01 PIN 인증 우회 | L456-499 | auth_methodology Part C | M3 C-1 판정 절차 1 (양호 기준 API 대조), title 명명 | ✅ |
| 사례 A-02 결제 비밀번호 하드코딩 | L456-499 내 | auth_methodology Part C | M3 C-1 판정표 "고정값 대체", 값 자체는 ↗ sec-scan-data | ✅ / ↗ |
| 사례 A-03 구매 제한 우회 | L501-521 | race_condition_methodology Part C | M4 D-4, D-9 개념 시나리오 형식 | ✅ |
| 사례 A-04 배치 API 무인증 | L523-541 | auth_methodology Part C | M2 A-3 [추가] 영향도별 심각도 표 | ✅ |
| 사례 A-05~A-07 | L543-596 | acl_methodology Part C | M2 B-2 (A-05 AOP 미동작, A-07 환경 우회), B-3 (A-06 contains) | ✅ |
| 인증 체크리스트 | L598-610 | auth_methodology Part D | M1 / M3 판정 요약표 | ✅ |
| 접근 제어 체크리스트 | L612-619 | acl_methodology Part D | M2 판정 요약표 | ✅ |
| Race Condition 체크리스트 | L621-625 | race_condition_methodology Part D | M4 판정 요약표 "횟수/수량 제한 API" 행 | ✅ |
| IDOR / 세션·토큰 전달 체크리스트 | L627-639 | auth_methodology Part D | M2 / M1 판정 요약표 | ✅ |
| 최종 판단 요약 | L641-712 내 | auth_methodology Part D | 각 모듈 판정 요약표, task_26 판정 기준 | ✅ |
| 부록 검색 명령어 | L641-712 내 | auth_methodology Part D | 각 모듈 grep 블록 | ✅ |

### 1-2. AUTHP5 — `MySkills/Auth_Analysis.md` (PHASE 5, 371줄)

| 원본 절 | 원문 보존 | 실행 반영 | 상태 |
|---|---|---|---|
| Scope (Hardcoded credentials → DataProtection) | auth_methodology Part A | M1 경계 규칙 | ↗ |
| 5-1 Authentication Mechanism Discovery | 〃 | M1 A-1 (+ 올바른 패턴 `requestMatchers(whitelist).permitAll().anyRequest().authenticated()`) | ✅ |
| 5-2 @Session Annotation Analysis | 〃 | M1 A-2 | ✅ |
| 5-3 Batch / Admin API Coverage (컨트롤러별 표) | 〃 | M2 A-3 + B-4 RULE-4 표 병합 | ✅ |
| 5-4 PIN / Password Server-Side Verification | 〃 | M3 C-1 (양호/취약 코드 예시 포함) | ✅ |
| 5-5 IDOR (4조건, 위험도) | 〃 | M2 A-5 | ✅ |
| 5-6 Session / Token Delivery Architecture | 〃 | M1 A-6 (헤더 키 기록, 내부 경로, Webview → M5) | ✅ |
| Final Verdict Summary Table | 〃 | 각 모듈 「판정 요약표」 → summary 「모듈별 판정 요약」 ("이상 없음" 기록 규칙 포함) | ✅ |
| Finding Report Format | 〃 | task_26 출력 형식 + title 작성 규칙 (`[PIN 검증 미흡] <API>` 등) | ✅ |

### 1-3. ACL — `MySkills/ACL_Analysis.md` (PHASE 4, 242줄)

| 원본 절 | 원문 보존 | 실행 반영 | 상태 |
|---|---|---|---|
| 4-1 Spring Security ACL | acl_methodology Part A | M2 B-1 (permitAll 범위, `hasIpAddress`, CSRF 근거) | ✅ |
| 4-2 Custom ACL Annotation | 〃 | M2 B-2 [추가] `@Target`/`@Retention`, `RequestNotFoundException` throw/catch, 환경 우회 심각도 | ✅ |
| 4-3 Vuln1 Host Header Spoofing | 〃 | M2 B-3 Vuln1 | ✅ |
| 4-3 Vuln2 contains() 부분 매칭 | 〃 | M2 B-3 Vuln2 | ✅ |
| 4-3 Vuln3 X-Forwarded-For | 〃 | M2 B-3 Vuln3 [추가] 프록시 존재 불명 시 Medium + needs-dynamic-verification | ✅ |
| 4-4 Full ACL Coverage Audit | 〃 | M2 B-4 [추가] `ip`/`host`/`regEx` 속성별 분류, regEx 전체 일치 판정, 이중 보호 | ✅ |
| Final Verdict Summary Table | 〃 | M2 판정 요약표 | ✅ |
| Finding Report Format | 〃 | task_26 출력 형식 | ✅ |

### 1-4. RACE — `MySkills/6. RACE_CONDITION_ANALYSIS.md` (575줄)

| 원본 절 | 원문 보존 | 실행 반영 | 상태 |
|---|---|---|---|
| 목차 L9-16 | 제외 (사유: 재구성된 파일 구조로 대체) | — | — |
| 1 개요·핵심 원칙·분석 대상 레이어 | race Part A | M4 서두 | 📎 |
| STEP 1 핵심 API 식별 (+ 상태 변경 GET) | 〃 | M4 D-1 [추가] 상태 변경 GET 처리 | ✅ |
| STEP 2-1 @Transactional 부재 (+ "더 정확한 방법") | 〃 | M4 D-2 [추가] Read 확인 순서 | ✅ |
| STEP 2-2 propagation 판정표 | 〃 | M4 D-2 [추가] 표 | ✅ |
| STEP 3 SELECT-then-Act | 〃 | M4 D-3 | ✅ |
| STEP 4 FOR UPDATE + 필요성 판정표 | 〃 | M4 D-4 [추가] 표 | ✅ |
| STEP 5 예외 묵살 | 〃 | M4 D-5 | ✅ |
| STEP 6 배치/정산 + 추가 항목 3종 + Redis | 〃 | M4 D-6 [추가] 상태 선점, 재실행 건너뛰기, Redis get→check→set | ✅ |
| STEP 7 DB 안전장치 표 | 〃 | M4 D-7 | ✅ |
| §3 판단 기준표 P1~P9 | 〃 | M4 각 절 판정 + 판정 요약표, task_26 판정 기준 | ✅ |
| §4 수정 위치 결정 트리 + 적용 위치 표 | 〃 | M4 D-9 recommendation 규칙 | ✅ |
| §5 보고서 작성 가이드 (명명 규칙, 항목 구성) | 〃 | M4 D-9 title/description/code_snippet 규칙 | ✅ |
| §6 체크리스트 Phase 1~6 (클래스 레벨 override 포함) | 〃 | M4 D-2 [추가] 클래스 레벨 override, 판정 요약표 | ✅ |
| 부록 패턴 A~C | 〃 | M4 D-2 / D-5 | ✅ |
| 부록 패턴 D (P8 판정표) | 〃 | M4 D-5 [추가] 표 | ✅ |
| 부록 패턴 E (P9 판정표) | 〃 | M4 D-6 [추가] 표 | ✅ |

### 1-5. WEBVIEW — `MySkills/WEBVIEW_SESSION_ANALYSIS.md` (= `5. webview-auth-session-analysis.md`, 627줄)

| 원본 절 | 원문 보존 | 실행 반영 | 상태 |
|---|---|---|---|
| 1 개요·범위 | webview Part A | M5 서두 | 📎 |
| 2.1 기술 스택 식별 / 2.3 초기 grep | 〃 | M0 R-1 / R-2 / R-4 | 📝 |
| 2.2 분석 도구 준비 | 〃 | — (도구 설치 안내, skill 실행에 불필요) | 📎 |
| 3.1 핵심 파일 탐색 순서 | 〃 | M0 R-3, M5 E-0 | 📝 |
| 3.2 흐름 추적 | 〃 | M5 E-0 | 📝 |
| 3.3 세션 검증 방식 분류 | 〃 | M5 E-0 → 「인증 아키텍처 요약」 | 📝 |
| 4.1 전제 (별개 컨텍스트) | 〃 | M5 서두 | 📎 |
| 4.2 앱 토큰 저장 위치 | 〃 | M5 E-1 판정표 | ✅ |
| 4.3 방식 1 extraHeaders (최초 로드 제약, 해결책 A~C) | 〃 | M5 E-2 방식 1 | ✅ |
| 4.3 방식 2 URL 파라미터 | 〃 | M5 E-2 방식 2 (M1 A-6과 병합) | ✅ |
| 4.3 방식 3 JS Bridge (CVE-2012-6636) | 〃 | M5 E-2 방식 3 | ✅ |
| 4.3 방식 4 쿠키 공유 (속성 5종) | 〃 | M5 E-2 방식 4 | ✅ |
| 4.3 방식 5 evaluateJavascript / postMessage | 〃 | M5 E-2 방식 5 | ✅ |
| 4.4 공통 흐름도 | 〃 | M5 E-4 | 📝 |
| 4.5 시나리오 A / 4.6 시나리오 B | 〃 | M5 E-4 | 📝 |
| 5.1 세션 출처 | 〃 | M5 E-1, E-4 | ✅ |
| 5.2 전달 방식 | 〃 | M5 E-2 | ✅ |
| 5.3 자동 로그인 구조 | 〃 | M5 E-2 [추가] 세션 공유 범위·로그아웃 동기화 | ✅ |
| 5.4 앱 토큰 vs 재발급 | 〃 | M5 E-0 (기록), E-4 | 📝 |
| 5.5 토큰 유효성 확인 | 〃 | M5 E-0 | 📝 |
| 5.6 채널 보안·피닝 | 〃 | M5 E-3 (피닝은 기록만) | ✅ / 📝 |
| 5.6 저장 보안 | 〃 | M5 E-1 | ✅ |
| 5.6 토큰 노출 경로 (로그) | 〃 | ↗ sec-scan-data PII Logging, URL은 E-2 방식 2 | ↗ / ✅ |
| 5.6 JS Bridge / evaluateJavascript | 〃 | M5 E-2 방식 3 / 5 | ✅ |
| 5.6 테스트/개발 우회 | 〃 | 서버: M1 A-2, 앱: M5 E-5 | ✅ |
| 5.6 CSRF | 〃 | M2 B-1 | ✅ |
| 5.6 내부 API 외부 차단 (prefix 매칭) | 〃 | M1 A-6 [추가] 내부 경로 차단 방식 | ✅ |
| 5.6 토큰 예측 가능성 | 〃 | M5 E-0 | ✅ |
| 5.6 로그 민감정보 | 〃 | ↗ sec-scan-data | ↗ |
| 6.1 / 6.2 기록 템플릿 | 〃 | M5 E-6 → summary 「인증 아키텍처 요약」 | 📝 |
| 6.3 취약점 발견 목록 | 〃 | task26_llm.json findings + 「모듈별 판정 요약」으로 대체 (상/중/하 → severity) | ✅ |
| 7 기술 스택별 탐색 포인트 | 〃 | M0 R-3, M5 E-0 grep | 📝 |

### 1-6. 사용자 결정으로 범위가 정해진 항목

| 항목 | 결정 | 반영 |
|---|---|---|
| 2차 인증·문자 인증 | 1-a: 코드 신호만 기록, 판정·테스트 절차 없음 | M3 C-2 `stepup_signals[]`, summary 「2차 인증·문자 인증 코드 신호」 |
| 동적 진단(DAST) 후보 | 2: 축소 방식 — 코드 신호 / 정적 확정 불가 사유 / 관련 finding만 | `dast_candidates.md`, `dast_candidates_AUTH.json`, RULE-5 |
| 실제 사례 | 익명화해서 포함 | methodology Part C (A-01~A-07), 식별정보 잔존 0 |
| 대상 스택 | Spring Boot/Kotlin 유지 | 모듈 grep (Java/Kotlin 중심, M5는 Android/iOS/Flutter/RN) |
| DAST 출력 위치 | 별도 파일, 공유 스키마·approve_report.py 미수정 | `dast_candidates_AUTH.json` (업로드·보고서 미연결) |

---

## Part 2. v1 skill 파일 → v2 (S10 「v2에 없는 라인」 분류)

`structure_report.txt` S10에서 v1 원문과 글자 그대로 일치하지 않는 라인을 분류한다.
분류: **이동**(다른 파일로 내용 이동, 문구 동일·유사) · **보강**(내용 유지 + 범위 확장) · **정정**(오류 수정) · **대체**(구조 변경으로 다른 표현으로 바뀜) · **삭제**(대응 없음)

### 2-1. v1 SKILL.md (26라인)

| v1 라인 | 내용 | 분류 | v2 위치 |
|---|---|---|---|
| L3 | frontmatter description | 보강 | Webview 세션 전달, 모듈 구조(M0~M5) 문구 추가 |
| L10 | Overview 한 줄 | 보강 | "Webview 세션 전달" 추가 + 모듈 표 |
| L20, L22 | references 목록 헤더 / task_26 설명 | 대체 | "항상 로드 / 실행 모듈만 / 애매할 때만" 3단 구분, task_26 = 공통 규칙 허브 |
| L55, L57 | 자율 완주 문구 | 보강 | "모듈 사이에서도 묻지 않는다", 구간에 M0·모듈 순차 추가 |
| L66 | 프론트엔드 repo 전량 skip | 이동 | Phase 2 M0 → `web-frontend` 분기 (규칙 동일) |
| L67 | PHP 등 Auto-Scan skip | 보강 | "(M0·LLM-Check는 수행)" 추가 |
| L74 | `--api-inventory` 줄 | 보강 | 뒤에 `--skip <auth_map.script_skip_args>` 추가 (줄 끝 `\` 때문에 불일치) |
| L91, L92 | 자동스캔 미탐지 한계 / "Section C" | 대체 | 한계 목록에 M1 A-6·M2 B-3·M3 C-2·M5 추가, "Section C" → "해당 모듈 파일" |
| L96 | task_26 전체 절차 준수 | 대체 | "공통 규칙은 task_26, 모듈은 module_plan 순서" |
| L98~L104 | LLM-Check Phase 1/2 설명 | 대체 | 모듈별 진행 1~5단계로 재구성 (cross_verification Phase 1/2, FP 이동, 수동진단(LLM) 출력 규칙 모두 포함) |
| L141, L143 | summary Finding 목록 표 헤더/예시 | 보강 | 「모듈」「검증상태」 열 추가 |
| L174 | `findings.read_text()` | 정정 | `read_text(encoding='utf-8')` — Windows cp949 기본 인코딩에서 한글 JSON 읽기 실패 방지 |
| L200, L220 | Phase C-1 접근 파일 구분 | 보강 | Phase 2(M0) 구분 추가 |
| L225 | "Phase C-1 완료 후 /sec-review로 진행" | 대체 | Step 5 "완료 요약 출력 후 대기, 자동 실행 금지" (CLAUDE.md BOUNDARY RULE) — **CHANGES R-1** |
| L231 | Resources의 task_26 | 보강 | "— 공통 규칙 허브" + 모듈·dast·methodology 추가 |

### 2-2. v1 task_26_auth_review.md (77라인)

| v1 라인 | 내용 | 분류 | v2 위치 |
|---|---|---|---|
| L1 | 제목 | 보강 | "— 공통 규칙 허브" |
| L4, L5 | 입력/출력 파일 | 보강 | 입력에 `auth_map.json`, 출력에 findings_AUTH / dast_candidates 추가 |
| L8~L11 | 3개 서브섹션 A/B/C | 대체 | 모듈 표 + 「v1 섹션 → 모듈 대응」 표 |
| L14 | 경계 문구 | 보강 | Webview 세션 전달 추가 + 「경계 (추가)」 하드코딩 값·로그·XSS |
| L20, L22, L24 | RULE-1 | 보강 | 대상에 `scan_pin_reverification`·PIN 추가, 공통 AOP/Interceptor 추적 |
| L29, L31~L34 | RULE-2 | 보강 | 모듈 위치 표기(M1 A-6 / M2 B-3 / M4 P2…), M3 C-2·M5 추가, B-2 Retention/regEx 추가 |
| L38, L42, L46, L48 | RULE-3 | 보강 | 대상에 stepup_signals·dast 파일, 인증번호, 헤더/설정 키 이름 마스킹 불필요 명시, "ACL 4-3" → "M2 B-3" |
| L54 | RULE-4 섹션 이름 | 보강 | "(표 형식은 M2 B-4)" |
| L77 | 스코프 제한 B-4 | 보강 | "M2 B-4" 표기 + auth_map·Gateway 스코프 규칙 추가 |
| L85~L94 | 컨텍스트 다이어그램 | 대체 | M0 → 스캐너(--skip 값 표기) → 모듈 매핑 다이어그램 |
| L101, L190, L255 | `## A.` / `## B.` / `## C.` 헤딩 | 이동 | M1·M2 / M2 / M4 |
| L147, L152, L153, L156 | A-4 PIN (헤딩, grep 2줄, 판정) | 이동·보강 | M3 C-1 — grep에 `Charge`/`Gift` 컨트롤러 추가, 판정표 6행으로 확장 |
| L257, L263, L265, L273, L282, L291, L301, L314 | C-1~C-7 헤딩·연결 문구 | 이동 | M4 D-1~D-7 (헤딩 번호 변경) |
| L271, L280, L289, L299, L312, L320 | C-2~C-7 판정 문구 | 이동·보강 | M4 D-2~D-7 판정 (P2 "중간~높음" → "Medium~High" + 금전 여부 기준) |
| L286 | FOR UPDATE grep | 보강 | M4 D-4 — `forUpdate` 패턴 추가 |
| L327~L337 | 완료 조건 자가 검증 | 보강 | 모듈 표기 + auth_map·verification_status·severity 조정 사유·summary 표 항목 추가 |
| L348~L352 | 판정 기준 표 5행 | 보강 | M1~M5 추가 항목 반영 (Gateway 헤더, Retention, regEx, Webview 등) |
| L400, L402 | assessment / consolidation_note | 보강 | PIN 후보 집계, stepup_signals, m4_handoff, dast 건수 추가 |
| L411, L413 | ID 규칙 BYP / SESS 설명 | 보강 | "Gateway 헤더", "(M1 A-6 / M5)" |
| L427 | 금지사항 민감정보 | 보강 | "인증번호" 추가 |
| L439 | code_snippet 기준 | 보강 | RACE 5~15줄 규칙 |
| L453~L456 | findings_AUTH 생성 절차 2~5 | 보강 | 병합 단계·dast 저장 단계 추가로 번호 변경 |
| L465, L467 | fn_disclaimer / summary | 보강 | Webview 문구, modules_run/skipped, `needs_dynamic_verification` |
| (S10 외) L358 | `affected_endpoints` 참조 경로 | 정정 | `shared/references/task_prompts/task_25...` → `sec-scan-data/references/task_prompts/task_25...` (실제 파일 위치) — **CHANGES F-1** |

### 2-3. v1 commands (4라인)

| v1 라인 | 분류 | v2 위치 |
|---|---|---|
| L3 description | 보강 | 웹뷰 세션·PIN, "구조 파악 후 해당 모듈만 실행" + `argument-hint` 추가 |
| L16, L17 | 보강 | "(공통 규칙 허브)", M0 읽기 단계 추가로 번호 변경 |
| L18 | 대체 | Phase 1 → M0 → Auto-Scan → 모듈 순차 → Summary, 완료 후 대기 |

**삭제 분류: 0건** — v1의 모든 라인이 이동·보강·정정·대체 중 하나로 v2에 대응한다.
