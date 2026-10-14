## Task: 2-6 인증/인가/접근제어/동시성 검토 (LLM 수동분석 보완) — 공통 규칙 허브

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: `state/<prefix>/task26_result.json` (scan_auth_access_control.py 자동스캔 결과), `state/<prefix>/auth_map.json` (M0 출력)
**출력 파일**:
- `state/<prefix>/task26_llm.json` (LLM 수동분석 보완 — supplemental)
- `state/<prefix>/findings_AUTH.json` (LLM-Check Phase 최종 출력 — /sec-review 대상)
- `state/<prefix>/dast_candidates_AUTH.json` (동적 확인 후보 — 진단자 참고용, 업로드·보고서 미연결)
**게시 방식**: `findings_AUTH.json`으로 통합하여 /sec-review 대상으로 전달

이 파일은 **모든 모듈이 따르는 공통 규칙**(HARD RULE, 탐색 지침, 심각도, 출력 형식)을 정의한다.
점검 절차와 항목별 판정 기준은 모듈 파일에 있다. 모듈은 `auth_map.module_plan`에 따라 실행한다.

| 모듈 | 파일 | 내용 | finding category |
|---|---|---|---|
| M0 auth-recon | `references/modules/m0_auth_recon.md` | 구조 파악 → `auth_map.json`, 모듈 실행 계획 (판정 없음) | — |
| M1 authn | `references/modules/m1_authn.md` | 인증 강제·@Session·Fail-Open·세션/토큰 전달구조 | `AUTH_BYPASS`, `SESSION_TOKEN_EXPOSURE`, `INTERNAL_API_EXPOSURE` |
| M2 authz-acl | `references/modules/m2_authz_acl.md` | 배치/관리자 인증·IDOR·Spring Security·@Acl·IP ACL | `IDOR`, `PRIVILEGE_ESCALATION`, `BROKEN_ACCESS_CONTROL`, `IP_ACL_BYPASS`, `INTERNAL_API_EXPOSURE` |
| M3 stepup-mfa | `references/modules/m3_stepup_mfa.md` | PIN·비밀번호 서버측 재검증, 2차 인증·문자 인증 코드 신호 기록 | `PIN_REVERIFICATION_MISSING` |
| M4 logic-race | `references/modules/m4_logic_race.md` | TOCTOU·트랜잭션·배치 동시성·보상 트랜잭션 (P1~P9) | `RACE_CONDITION` |
| M5 webview-client | `references/modules/m5_webview_client.md` | Native ↔ Webview 세션 전달·앱 토큰 저장·JS Bridge | `SESSION_TOKEN_EXPOSURE` |

> 모듈 판정이 애매하면 각 모듈 상단에 적힌 `references/methodology/*.md` 원문 절을 직접 읽고 판단한다 (원본 5개 MD의 원문 보존본, 익명화 적용).
> DAST 후보 기록 형식: `references/dast_candidates.md`

#### 기존 섹션 번호 → 모듈 대응 (v1 task_26 참조 호환)

| v1 섹션 | v2 위치 |
|---|---|
| A-1 / A-2 / A-6 | M1 A-1 / A-2 / A-6 |
| A-3 / A-5 | M2 A-3 / A-5 |
| A-4 (PIN 재검증) | M3 C-1 |
| B-1 ~ B-4 | M2 B-1 ~ B-4 |
| C-1 ~ C-7 (TOCTOU) | M4 D-1 ~ D-7 |
| (신규) | M3 C-2 / C-3, M4 D-8 / D-9, M5 E-0 ~ E-6 |

> **경계**: JWT 알고리즘/서명 결함, CORS 설정, DTO 필드 과다노출은 `sec-scan-data`(Task 2-5) 소관이다.
> 이 Task는 세션/어노테이션 기반 인증·인가·IP ACL·동시성 제어·Webview 세션 전달만 다룬다. JWT/CORS/DTO 관련 코드를 발견해도 finding을 생성하지 말고 `sec-scan-data` 영역임을 `manual_review_note`에만 메모한다.
> **경계 (추가)**: 하드코딩된 비밀번호/키/토큰 **값**과 로그의 세션 ID·개인정보 평문 기록도 `sec-scan-data` 소관이다 (메모만). Webview 페이지 자체의 XSS는 `sec-scan-xss` 소관이다.
> 단, 사용자 입력 PIN을 무시하고 고정값으로 대체하는 **인증 흐름**은 M3에서 `PIN_REVERIFICATION_MISSING`으로 판정한다.

---

### ⛔ HARD RULE — task26_llm.json 출력 전 반드시 준수 (생략·축약 절대 불가)

#### [RULE-1] 자동스캔 후보 — 반드시 코드 직접 확인 후 TP/FP 판정

자동스캔의 `scan_idor_candidates` / `scan_toctou_patterns` / `scan_pin_reverification`은 **정규식·파일 단위 후보 탐지**이며 `result: "정보"` + `needs_review: true`로 고정 출력된다. LLM은 각 후보에 대해:
1. `evidence.file`을 Read 툴로 직접 읽는다.
2. 서비스 레이어(공통 AOP/Interceptor 포함)까지 추적하여 세션 ID 대조 여부(IDOR), `@Transactional`/`FOR UPDATE` 존재 여부(RACE_CONDITION), PIN 확인 필드 검사 여부(PIN_REVERIFICATION_MISSING)를 확인한다.
3. **취약 확정** 조건을 충족하면 `result: "취약"` + `needs_review: false`로 상향, 미충족이면 `evidence_trail[]`로 이동(FP).

**금지**: 자동스캔의 `needs_review: true` 상태를 그대로 두고 finding만 복사 출력하는 것.

#### [RULE-2] 자동탐지 불가 항목 — 수동 심층진단 필수

아래 항목은 정규식 자동탐지 정확도가 낮거나 스캐너가 다루지 않는다. 모듈 파일에 명시된 grep 절차를 **LLM이 직접 실행**하여 코드를 확인한다:
- M1 A-6 (Auth 5-6 세션/토큰 전달구조 분류, 쿠키 플래그, Gateway 헤더 덮어쓰기, 외부 인증 서버 호출 URL) — 전체가 수동 판단
- M2 B-3 Vuln1 (Host Header Spoofing), Vuln3 (X-Forwarded-For 미처리), B-2 `@Retention`/`regEx` 판정 — 흐름 추적 필요
- M4 P2 (FOR UPDATE 부재), P3 (REQUIRES_NEW 단독), P6 (Redis 가드 부재), P8 (보상 트랜잭션 미구현), P9 (배치 최상위 트랜잭션 부재)
- M3 C-2 (2차 인증·문자 인증 코드 신호) — 스캐너 연결 없음
- M5 전체 — 스캐너는 서버 코드 대상이며 앱 코드를 다루지 않음

#### [RULE-3] 고객사 민감정보 마스킹 — finding 출력 전 필수

`evidence.code_snippet`, `manual_review_note`, `stepup_signals[]`, `dast_candidates_AUTH.json`에 아래 정보 원문 절대 포함 금지:

| 항목 | 마스킹 규칙 | 예시 |
|---|---|---|
| 세션ID·토큰·시크릿·인증번호 원문 | `[REDACTED]` 로 치환 | `sessionId=[REDACTED]` |
| 내부 IP 주소 (IPv4) | `[REDACTED_IP]` 로 치환 | `10.0.0.1` → `[REDACTED_IP]` |
| 내부 호스트명·도메인 | `[REDACTED_HOST]` 로 치환 | `internal.corp` → `[REDACTED_HOST]` |
| 실제 회원 ID/전화번호 등 PII 값 | `[REDACTED_PII]` 로 치환 | — |
| 변수명·파일경로·라인번호·헤더 키 이름·설정 키 이름 | 마스킹 불필요 | — |

> M2 B-3 findings는 `allowedIP` 목록에 실제 내부 IP가 포함되는 경우가 많다 — `code_snippet` 기재 전 반드시 `[REDACTED_IP]` 치환.

#### [RULE-4] review_note — 자동 보고서 포함용 마크다운 섹션 형식

`INTERNAL_API_EXPOSURE`(배치/관리자 API 전체 커버리지 감사) 카테고리의 finding은 `review_note` 필드에 `## 섹션 제목 + 마크다운 테이블` 형식으로 상세 데이터를 작성한다. `generate_final_report.py`가 `## ` 이후 구간을 Confluence `:::expand` 블록으로 자동 렌더링한다.

**권장 섹션 이름**: `## 무인증/무ACL 배치·관리자 엔드포인트 목록 (N건)` (표 형식은 M2 B-4)

#### [RULE-5] verification_status — 모든 finding에 기록

| 값 | 조건 |
|---|---|
| `code-confirmed` | 취약 조건을 이 repo의 코드·설정만으로 확인함 |
| `needs-dynamic-verification` | 판정이 배포 설정·인프라(프록시, DB 격리 수준, 인스턴스 수, DDL)·외부 서비스·원격 설정에 좌우되어 이 repo로 확정할 수 없음 |

- 기준은 각 모듈의 verification_status 절을 따른다.
- `needs-dynamic-verification` finding은 `dast_candidates_AUTH.json`에 후보로 함께 기록한다 (`references/dast_candidates.md`).
- DAST 후보에는 **코드 신호 / 정적으로 확정할 수 없는 이유 / 관련 finding**만 적는다. 테스트 절차·요청 예시·페이로드·성공 판정 기준은 작성하지 않는다.

#### [RULE-6] 심각도 조정 — 기본값에서 벗어날 때 근거 기록

- 기본 severity는 `vuln_taxonomy.md` Section 6과 아래 「판정 기준」 표를 따른다.
- 모듈 파일에 영향도 기반 조정 기준이 있는 경우(M2 A-3 배치 API 영향, M2 B-2 환경 우회, M2 B-3 사례 A-05/A-06, M3 C-1 금전 이동 여부, M4 P2, M5 방식별 등급)에만 조정한다.
- 조정 시 `manual_review_note`에 `severity 조정: <기본> → <조정> (사유: ...)`를 반드시 남긴다. 사유 없는 조정 금지.

---

### [데이터 탐색 지침] — 토큰 절약 필수

> **원시 JSON 전체를 컨텍스트에 로드하지 말 것.**

1. **먼저 요약본만 로드**: `state/<prefix>/task26_llm_summary.json`을 읽는다. 전체 건수·severity별/category별 통계, 카테고리별 대표 샘플 1~2건을 포함한다.
   - category 코드: `IDOR`, `PRIVILEGE_ESCALATION`, `AUTH_BYPASS`, `PIN_REVERIFICATION_MISSING`, `SESSION_TOKEN_EXPOSURE`, `BROKEN_ACCESS_CONTROL`, `IP_ACL_BYPASS`, `INTERNAL_API_EXPOSURE`, `RACE_CONDITION`
2. **상세 데이터가 필요할 때만 원본 접근**: `full_result_path`를 `offset`/`limit`으로 조회.
3. **탐색 우선순위**: `severity: Critical/High` → `result: 취약` → `result: 정보(needs_review)` 순.
4. **엔드포인트 목록은 `auth_map.endpoints[]`를 우선 사용**한다. 같은 grep을 모듈마다 반복하지 않는다.
5. **모듈 파일은 실행하는 것만 읽는다**. `module_plan.Mx.run == false`인 모듈 파일은 로드하지 않는다.

> 📋 **Finding 작성 기준**: `shared/references/finding_writing_guide.md` 필수 준수
> 📋 **취약점 분류 기준**: `shared/references/vuln_taxonomy.md` Section 6 필수 참조
> - `scope.type` 매핑: IDOR/PRIVILEGE_ESCALATION/AUTH_BYPASS/PIN_REVERIFICATION_MISSING/INTERNAL_API_EXPOSURE/RACE_CONDITION → `endpoint` | SESSION_TOKEN_EXPOSURE/IP_ACL_BYPASS → `file` | BROKEN_ACCESS_CONTROL → `config`

---

### ⚠️ 모듈 스코프 제한 시 필수 절차

`DIAGNOSIS_SCOPE`가 repo 전체가 아닌 특정 서브모듈/패키지로 제한된 경우:
- **Step 0**: 자동스캔 결과 중 `evidence.file`이 스코프 밖 경로인 항목을 필터링해 검토 대상에서 제외한다.
- M0의 `auth_map.endpoints[]`도 스코프 내 경로만 기록한다.
- 배치/관리자 컨트롤러 커버리지 감사(M2 B-4)는 스코프 내 컨트롤러만 대상으로 한다.
- 인증 강제 메커니즘(M1 A-1)·Gateway가 스코프 밖에 있으면 위치만 기록하고 판정은 스코프 내 코드에 대해서만 한다.

---

### 컨텍스트

```
M0 auth-recon ──→ auth_map.json (repo 유형 · 인증 흐름 플래그 · 엔드포인트 · module_plan · script_skip_args)
                      ↓ --skip <script_skip_args>
자동스캔 (scan_auth_access_control.py)
  ├─ scan_missing_session_annotation  (--skip session)    ─┐
  ├─ scan_test_session_bypass         (--skip testbypass)  ├→ M1 authn
  ├─ scan_pin_reverification          (--skip pin)        ──→ M3 stepup-mfa
  ├─ scan_idor_candidates             (--skip idor)       ─┐
  ├─ scan_permitall_antmatchers       (--skip permitall)   │
  ├─ scan_ip_acl_bypass               (--skip ipacl)       ├→ M2 authz-acl
  ├─ scan_missing_acl_admin_batch     (--skip aclcoverage)─┘
  └─ scan_toctou_patterns             (--skip toctou)     ──→ M4 logic-race
                                        (스캐너 없음)      ──→ M5 webview-client, M3 C-2
                      ↓
     LLM 교차검증 + 수동 심층진단 (모듈별 grep 절차 직접 실행)
                      ↓
  task26_llm.json → findings_AUTH.json
                 └→ dast_candidates_AUTH.json (needs-dynamic-verification + M3 C-2)
```

**모듈 실행 순서**: M0 → M1 → M2 → M3 → M4 → M5.
M3 C-3 `m4_handoff[]`는 M4 D-1 입력이 되고, M1 A-6에서 Webview 구조가 확인되면 `module_plan.M5.run`을 `true`로 갱신한다.
여러 모듈에서 같은 코드 위치·같은 원인의 finding이 나오면 **한 건으로 병합**하고 다른 모듈의 증거는 `evidence_trail[]`에 둔다 (예: M1 A-6 URL 세션 노출 ↔ M5 E-2 방식 2, M1 A-6 TLS ↔ M5 E-3).

---

### ⚠️ 완료 조건 자가 검증 (필수 — 미충족 시 Task 미완료)

```
□ auth_map.json 존재, module_plan의 모든 모듈에 run/reason 기재
  - skip 모듈은 summary 「모듈별 판정 요약」에 "해당없음(사유)" 기록

□ RULE-1 대상 후보(M2 A-5 IDOR / M4 D-2~D-7 RACE_CONDITION / M3 C-1 PIN) 전건에 대해 Read 툴로 코드 직접 확인 완료
  - 미확인 상태로 needs_review: true 유지한 채 finding 생성 금지

□ 자동탐지 불가 항목(RULE-2) 중 실행 모듈에 속한 것 전체 수동 확인 완료
  - M1 A-6, M2 B-3 Vuln1/Vuln3, M4 P2/P3/P6/P8/P9, M3 C-2, M5 각각 grep 절차 실행 후 판정 기재

□ M2 B-4 전체 ACL 커버리지 감사 결과 review_note에 마크다운 테이블 섹션(RULE-4) 작성

□ 모든 finding에 verification_status 기재 (RULE-5)
  - needs-dynamic-verification finding 전건이 dast_candidates_AUTH.json에 존재
  - dast_candidates_AUTH.json에 테스트 절차·페이로드 미포함 확인

□ 기본값과 다른 severity 전건에 manual_review_note 조정 사유 기재 (RULE-6)

□ IP·세션·토큰 관련 evidence.code_snippet / stepup_signals / dast 후보 전체 마스킹 확인 (RULE-3)

□ JWT/CORS/DTO·하드코딩 값·로그 노출·Webview XSS 관련 코드 발견 시 finding 미생성, 경계 노트만 기재 확인

□ findings 배열이 비어 있지 않은 경우 각 finding에 evidence.file(실제 경로) 기재 필수

□ 실행한 모듈마다 summary 「모듈별 판정 요약」 표의 전 행에 양호/취약(finding_id)/이상 없음/해당없음 기재
```

---

### 판정 기준

| 심각도 | 조건 |
|---|---|
| **Critical** | 전역 인증 강제 완전 부재, 결제/취소 API @Session 누락, 테스트 세션 우회 비게이팅, 인증서버 Fail-Open, 배치/관리자 API 무인증+무ACL(금전·회원상태 영향), Gateway 내부 헤더 외부 덮어쓰기 가능 |
| **High** | IDOR(취소/삭제/개인정보), PIN 재검증 누락, IP ACL 우회(Host spoofing/contains 부분매칭/regEx 부분일치/XFF 미처리), 내부 API @Acl 누락·AOP 미동작, `@Retention` RUNTIME 아님, 내부 경로 차단 없음·prefix 비교만, RACE_CONDITION P1/P3/P4/P7/P8/P9, 세션 ID 예측 가능, Webview: 임의 URL로 토큰 전송·도메인 제한 없는 JS Bridge·`postMessage(..., '*')`·SSL 오류 무시·전역 cleartext + http 토큰 전달·외부 저장소 토큰·앱 고정 토큰/인증 생략 |
| **Medium** | `anyRequest().permitAll()` 단일방어선, ACL local/dev 비활성화(외부 비접근 서버), csrf 근거불명 비활성화, 세션 URL노출, 쿠키 플래그 미설정, TLS 미적용 구간, 프록시 환경 XFF 미신뢰, RACE_CONDITION P2(금전 외)/P5/P6, PIN 유효시간 과다·금전 외 정보변경 PIN 누락, 배치 API 무인증(캐시 재구성 등 가용성 영향만), Webview: 평문 저장소 토큰·도메인 제한 있는 JS Bridge·쿠키 플래그 누락·`window` 전역 토큰·전역 cleartext(https 전달)·운영 Webview 원격 디버깅 |
| **Low** | IDOR(개인정보 미포함 조회), 과도한 permitAll() 범위, 로그아웃 시 토큰·Webview 세션 미삭제 |
| **Info** | 세션/토큰 전달구조 분류 참고사항, DB 안전장치 부분 적용, 외부 인증 서버 호출 URL에 요청 값 반영(SSRF 가능성 — 사람 검토), 정적 확정 불가 항목(`needs-dynamic-verification` + `result: "정보"`) |

> 같은 항목이 모듈 파일과 이 표에 모두 있으면 **모듈 파일의 세부 기준이 우선**한다 (영향도 조정 포함, RULE-6).

---

### 출력 형식

> **`affected_endpoints` 작성 규칙 (전체 Task 공통)**: `sec-scan-data/references/task_prompts/task_25_data_protection.md`의 규칙과 동일 (v1의 `shared/...` 경로는 실제 파일 위치와 달라 정정) — `method`/`path`(필수)/`controller`/`description` 필드. 전역 영향은 `"path": "전역 (전체 API)"` 1건 기재.

```json
{
  "task_id": "auth",
  "status": "completed",
  "findings": [
    {
      "id": "AUTH-IDOR-001",
      "title": "IDOR — 주문 취소 API에서 요청 mbrId를 세션과 대조하지 않음",
      "severity": "High",
      "category": "IDOR",
      "source_module": "M2",
      "description": "OrderController.cancel()이 @RequestParam mbrId를 세션의 userInfo.mbrId와 비교하지 않고 그대로 WHERE 절에 사용해 타인의 주문을 취소 가능.",
      "affected_endpoints": [
        {
          "method": "POST",
          "path": "/api/v1/order/cancel",
          "controller": "OrderController.cancel()",
          "description": "요청 파라미터 mbrId로 타 회원 주문 취소 가능"
        }
      ],
      "evidence": {
        "file": "src/main/kotlin/.../OrderController.kt",
        "lines": "88",
        "code_snippet": "fun cancel(@RequestParam mbrId: String, @RequestParam orderId: String) {\n    orderService.cancel(mbrId, orderId)\n}"
      },
      "cwe_id": "CWE-639",
      "owasp_category": "A01:2021 Broken Access Control",
      "diagnosis_method": "교차검증(수동)",
      "result": "취약",
      "needs_review": false,
      "verification_status": "code-confirmed",
      "manual_review_note": "OrderService.cancel() 내부에서 userInfo.mbrId 대조 로직 부재 확인.",
      "recommendation": "1. WHERE 절의 mbrId를 요청 파라미터 대신 세션의 userInfo.mbrId로 교체.\n2. 서비스 레이어 진입 시 requestMbrId == sessionMbrId 검증 추가."
    }
  ],
  "auth_access_assessment": {
    "auth_map_path": "state/<prefix>/auth_map.json",
    "modules_run": ["M0", "M1", "M2", "M3", "M4"],
    "modules_skipped": { "M5": "해당없음(Webview 구조 없음)" },
    "global_auth_enforcement": "spring_security | aop_annotation | interceptor | none",
    "test_session_bypass_gated": true,
    "acl_env_bypass": false,
    "idor_candidates_confirmed": 1,
    "idor_candidates_fp": 2,
    "pin_candidates_confirmed": 0,
    "pin_candidates_fp": 0,
    "race_condition_candidates_confirmed": 0,
    "race_condition_candidates_fp": 0,
    "stepup_signals": [],
    "m4_handoff": [],
    "dast_candidates_count": 0
  },
  "consolidation_note": "자동스캔 후보 N건 중 IDOR M건/PIN P건/RACE_CONDITION K건 코드 확인 후 확정. 원본은 state/<prefix>/task26_result.json 보존.",
  "executed_at": "",
  "claude_session": ""
}
```

- `source_module` / `verification_status`는 v2 추가 필드다. `findings_AUTH.json`에도 그대로 옮긴다 (스키마 검증은 추가 필드를 허용).
- `stepup_signals[]` 형식: M3 C-2 신호 키 표. `m4_handoff[]` 형식: M3 C-3.

**ID 명명 규칙:**
- `AUTH-IDOR-NNN` — IDOR 확정 건
- `AUTH-PRIV-NNN` — PRIVILEGE_ESCALATION (배치/관리자 인증 누락)
- `AUTH-BYP-NNN` — AUTH_BYPASS (전역 인증우회/Fail-Open/테스트세션/Gateway 헤더)
- `AUTH-PIN-NNN` — PIN_REVERIFICATION_MISSING
- `AUTH-SESS-NNN` — SESSION_TOKEN_EXPOSURE (M1 A-6 / M5)
- `AUTH-BAC-NNN` — BROKEN_ACCESS_CONTROL (permitAll/CSRF)
- `AUTH-IPACL-NNN` — IP_ACL_BYPASS
- `AUTH-IAE-NNN` — INTERNAL_API_EXPOSURE
- `AUTH-RACE-NNN` — RACE_CONDITION

**title 작성 규칙 (원본 보고서 명명 매핑)**:
- RACE_CONDITION: `비즈니스 로직 우회 - [기능명] - [취약 원인]` (M4 D-9)
- PIN_REVERIFICATION_MISSING: `[PIN 검증 미흡] <API 경로>` (M3 C-1)
- 그 외: `<취약점 유형> — <대상> <원인>` (위 예시 형식)

**주의**:
- 원본 자동스캔 JSON(`state/<prefix>/task26_result.json`)은 수정하지 않는다. 증적 보존용.
- 확정/보완 findings는 모두 이 LLM 파일(`state/<prefix>/task26_llm.json`)에만 작성한다.

---

### 금지사항
- 추측 금지 (코드 근거 필수)
- 민감정보(세션ID/토큰/인증번호/내부 IP/PII) 원문 포함 금지 → RULE-3 마스킹 규칙 적용
- 자동 스캔 결과를 번복할 때는 코드 근거 명시 필수
- 스크립트가 이미 판정한 "양호" 항목은 재검토 불필요
- JWT/CORS/DTO 영역 finding 생성 금지 (sec-scan-data 소관)
- M3 C-2(2차 인증·문자 인증)에서 finding 생성·우회 판정·테스트 절차 작성 금지
- `dast_candidates_AUTH.json`에 테스트 절차·요청 예시·페이로드·성공 판정 기준 작성 금지
- `module_plan`에서 skip된 모듈의 finding 생성 금지 (사용자가 `--only`로 지정한 경우 제외)

---

### 코드 증적 품질 기준 (필수 준수)

> ⚠️ **evidence.file은 반드시 실제 파일 경로여야 한다. evidence.code_snippet은 반드시 Read 툴로 읽은 실제 파일 내용을 사용한다.**

- `evidence.file`: repo root 기준 전체 상대경로 필수
- `evidence.code_snippet`: Read 툴로 직접 읽은 실제 코드만 허용 (RACE_CONDITION은 5~15줄 이내 — M4 D-9)
- 파일을 직접 읽지 못한 경우: `needs_review: true` + `manual_review_note: "코드 미확인"` 표시

---

## findings_AUTH.json 생성 (LLM-Check Phase 최종 출력)

LLM-Check Phase 완료 후 `state/<prefix>/findings_AUTH.json`을 생성한다.

### 절차

1. `state/<prefix>/task26_result.json`의 `auto_findings[]` 로드
2. 각 항목 LLM 교차검증 수행:
   - **FP 판정**: `findings[]`에서 제거, `evidence_trail[]`에 `fp_corrected: true`로 기록
   - **TP 확정**: description, code_snippet, evidence 보강 (RULE-1 대상 후보는 코드 직접 확인)
3. Auto-Scan 미탐지 취약점(FN) 발견 시 신규 finding 추가: `fn_detected: true`, `source: "llm-check(fn-detected)"` (M5 전체, M1 A-6 등 수동 항목 포함)
4. 여러 모듈 중복 finding 병합 (위 「컨텍스트」 병합 규칙)
5. finding_id 재부여: `AUTH-001` 순번 (심각도 내림차순)
6. `state/<prefix>/findings_AUTH.json` 저장
7. `state/<prefix>/dast_candidates_AUTH.json` 저장 (`related_findings`는 재부여된 `AUTH-NNN` ID로 갱신, 0건이어도 빈 배열로 생성)

### 출력 스키마 (shared/references/output_schemas.md 참조)

```json
{
  "task_id": "auth",
  "generated_at": "ISO8601",
  "scan_coverage": {
    "fn_disclaimer": "Auto-Scan은 정적 패턴 기반이므로 흐름 분석이 필요한 FOR UPDATE 부재(P2)/REQUIRES_NEW 단독(P3,P9)/Redis 가드부재(P6)/보상트랜잭션 미구현(P8), Host Header Spoofing(ACL 4-3 Vuln1), 세션/토큰 전달구조(Auth 5-6), Webview 세션 전달(앱 코드)은 후보 탐지 정확도가 낮거나 스캐너 범위 밖이라 LLM 수동 심층진단으로 보완함",
    "modules_run": ["M0", "M1", "M2", "M3", "M4"],
    "modules_skipped": { "M5": "해당없음(Webview 구조 없음)" }
  },
  "summary": { "total": 0, "취약": 0, "정보": 0, "fn_detected": 0, "needs_dynamic_verification": 0 },
  "llm_checked": true,
  "findings": [
    {
      "finding_id": "AUTH-001",
      "title": "",
      "severity": "Critical|High|Medium|Low|Informational",
      "risk_level": 5,
      "category": "IDOR|PRIVILEGE_ESCALATION|AUTH_BYPASS|PIN_REVERIFICATION_MISSING|SESSION_TOKEN_EXPOSURE|BROKEN_ACCESS_CONTROL|IP_ACL_BYPASS|INTERNAL_API_EXPOSURE|RACE_CONDITION",
      "cwe_id": "CWE-639|CWE-269|CWE-287|CWE-862|CWE-598|CWE-290|CWE-749|CWE-367",
      "owasp_category": "A01:2021 Broken Access Control|A07:2021 Identification and Authentication Failures|A04:2021 Insecure Design",
      "result": "취약|정보",
      "diagnosis_method": "자동스캔(SAST)|교차검증(수동)|수동진단(LLM)",
      "source": "auto-scan|llm-check|llm-check(fn-detected)",
      "source_module": "M1|M2|M3|M4|M5",
      "verification_status": "code-confirmed|needs-dynamic-verification",
      "fn_detected": false,
      "fp_corrected": false,
      "scope": {
        "type": "endpoint|file|config",
        "endpoint": "/api/v1/order/cancel",
        "file": "path/to/OrderController.kt",
        "line": 88,
        "module": null
      },
      "description": "한국어 설명",
      "recommendation": "조치 방법",
      "evidence": {
        "file": "path/to/OrderController.kt",
        "line": 88,
        "code_snippet": "실제 코드 (마스킹 적용)"
      },
      "needs_review": false
    }
  ],
  "evidence_trail": []
}
```
