## Task: 2-6 인증/인가/접근제어/동시성 검토 (LLM 수동분석 보완)

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: `state/<prefix>/task26_result.json` (scan_auth_access_control.py 자동스캔 결과)
**출력 파일**: `state/<prefix>/task26_llm.json` (LLM 수동분석 보완 — supplemental)
**게시 방식**: `findings_AUTH.json`으로 통합하여 /sec-review 대상으로 전달

이 Task는 3개 서브섹션으로 구성된다:
- **A. 인증/세션/IDOR** — @Session, 전역 인증우회, PIN 재검증, IDOR, 세션/토큰 전달구조
- **B. 접근제어/ACL** — Spring Security ACL, 커스텀 @Acl, IP 기반 ACL 우회, 전체 ACL 커버리지
- **C. TOCTOU/동시성** — @Transactional 범위, SELECT-then-Act, FOR UPDATE, 예외 묵살, 배치 동시성

> **경계**: JWT 알고리즘/서명 결함, CORS 설정, DTO 필드 과다노출은 `sec-scan-data`(Task 2-5) 소관이다.
> 이 Task는 세션/어노테이션 기반 인증·인가·IP ACL·동시성 제어만 다룬다. JWT/CORS/DTO 관련 코드를 발견해도 finding을 생성하지 말고 `sec-scan-data` 영역임을 `manual_review_note`에만 메모한다.

---

### ⛔ HARD RULE — task26_llm.json 출력 전 반드시 준수 (생략·축약 절대 불가)

#### [RULE-1] IDOR / RACE_CONDITION 후보 — 반드시 코드 직접 확인 후 TP/FP 판정

자동스캔의 `scan_idor_candidates` / `scan_toctou_patterns`는 **정규식 기반 후보 탐지**이며 `result: "정보"` + `needs_review: true`로 고정 출력된다. LLM은 각 후보에 대해:
1. `evidence.file`을 Read 툴로 직접 읽는다.
2. 서비스 레이어까지 추적하여 세션 ID 대조 여부(IDOR) 또는 `@Transactional`/`FOR UPDATE` 존재 여부(RACE_CONDITION)를 확인한다.
3. **취약 확정** 조건을 충족하면 `result: "취약"` + `needs_review: false`로 상향, 미충족이면 `evidence_trail[]`로 이동(FP).

**금지**: 자동스캔의 `needs_review: true` 상태를 그대로 두고 finding만 복사 출력하는 것.

#### [RULE-2] Auth 5-6 / ACL 4-3 Vuln1-3 / Race P2·P3·P6·P8·P9 — 자동탐지 불가 항목 수동 심층진단 필수

아래 항목은 정규식 자동탐지 정확도가 낮아 스크립트가 후보조차 만들지 않거나 낮은 confidence로만 탐지한다. Section A/B/C에 명시된 grep 절차를 **LLM이 직접 실행**하여 코드를 확인한다:
- Auth 5-6 (세션/토큰 전달구조 분류) — 전체가 수동 판단
- ACL 4-3 Vuln1 (Host Header Spoofing), Vuln3 (X-Forwarded-For 미처리) — 흐름 추적 필요
- Race P2 (FOR UPDATE 부재), P3 (REQUIRES_NEW 단독), P6 (Redis 가드 부재), P8 (보상 트랜잭션 미구현), P9 (배치 최상위 트랜잭션 부재)

#### [RULE-3] 고객사 민감정보 마스킹 — finding 출력 전 필수

`evidence.code_snippet` 및 `manual_review_note`에 아래 정보 원문 절대 포함 금지:

| 항목 | 마스킹 규칙 | 예시 |
|---|---|---|
| 세션ID·토큰·시크릿 원문 | `[REDACTED]` 로 치환 | `sessionId=[REDACTED]` |
| 내부 IP 주소 (IPv4) | `[REDACTED_IP]` 로 치환 | `10.0.0.1` → `[REDACTED_IP]` |
| 내부 호스트명·도메인 | `[REDACTED_HOST]` 로 치환 | `internal.corp` → `[REDACTED_HOST]` |
| 실제 회원 ID/전화번호 등 PII 값 | `[REDACTED_PII]` 로 치환 | — |
| 변수명·파일경로·라인번호 | 마스킹 불필요 | — |

> ACL 4-3 findings는 `allowedIP` 목록에 실제 내부 IP가 포함되는 경우가 많다 — `code_snippet` 기재 전 반드시 `[REDACTED_IP]` 치환.

#### [RULE-4] review_note — 자동 보고서 포함용 마크다운 섹션 형식

`INTERNAL_API_EXPOSURE`(배치/관리자 API 전체 커버리지 감사) 카테고리의 finding은 `review_note` 필드에 `## 섹션 제목 + 마크다운 테이블` 형식으로 상세 데이터를 작성한다. `generate_final_report.py`가 `## ` 이후 구간을 Confluence `:::expand` 블록으로 자동 렌더링한다.

**권장 섹션 이름**: `## 무인증/무ACL 배치·관리자 엔드포인트 목록 (N건)`

---

### [데이터 탐색 지침] — 토큰 절약 필수

> **원시 JSON 전체를 컨텍스트에 로드하지 말 것.**

1. **먼저 요약본만 로드**: `state/<prefix>/task26_llm_summary.json`을 읽는다. 전체 건수·severity별/category별 통계, 카테고리별 대표 샘플 1~2건을 포함한다.
   - category 코드: `IDOR`, `PRIVILEGE_ESCALATION`, `AUTH_BYPASS`, `PIN_REVERIFICATION_MISSING`, `SESSION_TOKEN_EXPOSURE`, `BROKEN_ACCESS_CONTROL`, `IP_ACL_BYPASS`, `INTERNAL_API_EXPOSURE`, `RACE_CONDITION`
2. **상세 데이터가 필요할 때만 원본 접근**: `full_result_path`를 `offset`/`limit`으로 조회.
3. **탐색 우선순위**: `severity: Critical/High` → `result: 취약` → `result: 정보(needs_review)` 순.

> 📋 **Finding 작성 기준**: `shared/references/finding_writing_guide.md` 필수 준수
> 📋 **취약점 분류 기준**: `shared/references/vuln_taxonomy.md` Section 6 필수 참조
> - `scope.type` 매핑: IDOR/PRIVILEGE_ESCALATION/AUTH_BYPASS/PIN_REVERIFICATION_MISSING/INTERNAL_API_EXPOSURE/RACE_CONDITION → `endpoint` | SESSION_TOKEN_EXPOSURE/IP_ACL_BYPASS → `file` | BROKEN_ACCESS_CONTROL → `config`

---

### ⚠️ 모듈 스코프 제한 시 필수 절차

`DIAGNOSIS_SCOPE`가 repo 전체가 아닌 특정 서브모듈/패키지로 제한된 경우:
- **Step 0**: 자동스캔 결과 중 `evidence.file`이 스코프 밖 경로인 항목을 필터링해 검토 대상에서 제외한다.
- 배치/관리자 컨트롤러 커버리지 감사(B-4)는 스코프 내 컨트롤러만 대상으로 한다.

---

### 컨텍스트

```
자동스캔 (scan_auth_access_control.py)
  ├─ scan_missing_session_annotation  ─┐
  ├─ scan_test_session_bypass          │→ A. 인증/세션/IDOR
  ├─ scan_pin_reverification           │
  ├─ scan_idor_candidates             ─┘
  ├─ scan_permitall_antmatchers       ─┐
  ├─ scan_ip_acl_bypass                │→ B. 접근제어/ACL
  ├─ scan_missing_acl_admin_batch     ─┘
  └─ scan_toctou_patterns             ──→ C. TOCTOU/동시성
                ↓
     LLM 교차검증 + 수동 심층진단 (grep 절차 직접 실행)
                ↓
        task26_llm.json → findings_AUTH.json
```

---

## A. 인증/세션/IDOR

### A-1. 인증 강제 메커니즘 파악 (Auth 5-1)

```bash
grep -rn "@interface\|annotation class" src/ --include="*.java" --include="*.kt" -n
grep -rn "@Aspect\|@Before\|@Around\|@After\|Advisor" src/ --include="*.java" --include="*.kt" -B 1 -A 5
grep -rn "SecurityFilterChain\|WebSecurityConfigurerAdapter\|@EnableWebSecurity" src/ --include="*.java" --include="*.kt" -l
grep -rn "addInterceptors\|HandlerInterceptor\|InterceptorRegistry" src/ --include="*.java" --include="*.kt" -A 10
grep -rn "@Pointcut\|execution(" src/ --include="*.java" --include="*.kt" -A 3
grep -rn "anyRequest().*permitAll()\|anyRequest\(\)\.permitAll\|anyRequest\(\)\s*\.\s*permitAll" src/ --include="*.java" --include="*.kt" -B 5 -A 2
```

**판정**:
- 인증 강제 유형 분류: Spring Security 전역(낮음) / AOP+파라미터 어노테이션(높음) / Interceptor(중간) / 전역 강제 없음(치명)
- AOP Pointcut 범위: 클래스 레벨(전체 적용) vs 파라미터 레벨(누락 시 해당 메서드만 무인증)
- `anyRequest().permitAll()` 패턴 발견 시 → **AUTH_BYPASS, 취약, Medium** — Spring Security 인가 레이어가 무력화되고 커스텀 필터 단일 방어선에만 의존

### A-2. @Session 어노테이션 분석 (Auth 5-2)

```bash
grep -rn "@Session" src/ --include="*.java" --include="*.kt" -n
grep -rn "@Session" src/ --include="*.java" --include="*.kt" | grep "required\s*=\s*false\|required\s*=\s*true"
grep -rn "@PostMapping\|@PutMapping\|@DeleteMapping" src/ --include="*.java" --include="*.kt" | grep -i "pay\|purchase\|cancel\|batch\|admin\|settle\|order\|refund"
grep -rn "TEST_ID\|startsWith.*ID\|mock.*session\|testSession\|TEST_SESSION" src/ --include="*.java" --include="*.kt" -A 5
grep -rn "TEST_ID\|startsWith.*ID" src/ --include="*.java" --include="*.kt" -A 10 | grep -i "active\|profile\|env\|local\|dev"
grep -rn "timeout\|fallback\|catch.*[Ss]ession\|null.*UserInfo\|InvalidSession\|catch.*[Aa]uth" src/ --include="*.java" --include="*.kt" -A 5
grep -rn "acceptsProfiles\|getActiveProfiles\|activeProfiles" src/ --include="*.java" --include="*.kt" -B 5 -A 10
```

**판정**:
- 결제/취소/정산 API에 `required = false` 또는 `@Session` 누락 → **AUTH_BYPASS, 취약, Critical**
- 테스트 세션 우회(`TEST_ID:` 등)가 local/dev 프로파일 게이팅 없이 존재 → **AUTH_BYPASS, 취약, Critical** (임의 사용자 사칭 가능)
- 인증 서버 타임아웃 시 Fail-Open(인증 통과) 또는 null UserInfo 통과 → **AUTH_BYPASS, 취약, Critical**
- `!env.acceptsProfiles("prod")` 등으로 인증 서버 응답을 강제 성공 처리 → **AUTH_BYPASS, 취약, Critical**. 전 환경 동일 JWT 시크릿 병존 시 dev 발급 토큰이 prod에서도 유효 — 연계 위험으로 함께 보고

### A-3. 배치/관리자 API 인증 커버리지 (Auth 5-3)

```bash
find src/ -name "*Batch*Controller*" -o -name "*Admin*Controller*" -o -name "*Internal*Controller*" -o -name "*Manage*Controller*" 2>/dev/null
grep -rn "@PostMapping\|@GetMapping\|@PutMapping\|@DeleteMapping\|@RequestMapping" src/ --include="*.java" --include="*.kt" -B 10 | grep -B 9 "batch\|admin\|internal\|system\|settle\|cron" | grep -v "@Session\|@PreAuthorize\|@Secured"
grep -rn "@RestController\|@Controller" src/ --include="*.java" --include="*.kt" -l | xargs grep -L "@Session\|@PreAuthorize\|@Secured\|@LoginUser" 2>/dev/null
```

**판정**: `@Session`과 `@Acl` 모두 누락 → **PRIVILEGE_ESCALATION, 취약, Critical** (무인증 접근 가능). `@Session` 없고 `@Acl`만 있음 → B-3(IP ACL) 절차로 우회가능성 확인 후 판정.

### A-4. PIN/비밀번호 서버측 재검증 (Auth 5-4)

```bash
grep -rn "pinConfirmationDate\|passwordConfirmationDate\|pinStatus\|pinVerified\|pinTime" src/ --include="*.java" --include="*.kt" -n
grep -rn "pinConfirmationDate\|passwordConfirmationDate" src/ --include="*.java" --include="*.kt" -B 3 -A 10
grep -rn "class.*Pay.*Controller\|class.*Purchase.*Controller\|class.*Order.*Controller" src/ --include="*.java" --include="*.kt" -l | xargs grep -L "pinConfirmationDate\|passwordConfirmationDate" 2>/dev/null
grep -rn "class.*Request\|data class.*Request" src/ --include="*.java" --include="*.kt" | grep -i "pay\|purchase\|order\|join" | awk -F: '{print $1}' | sort -u | xargs grep -l "pin\|password\|secret" 2>/dev/null
```

**판정**: 결제/고액/정보변경 API에서 `pinConfirmationDate`(또는 동등 필드) 시간 재검증 없음 → **PIN_REVERIFICATION_MISSING, 취약, High**. Request DTO에 PIN/password 필드 자체가 없음(UI 레벨만 강제) → **PIN_REVERIFICATION_MISSING, 취약, High**.

### A-5. IDOR (Auth 5-5)

```bash
grep -rn "@PathVariable\|@RequestParam" src/ --include="*.java" --include="*.kt" | grep -i "mbrId\|userId\|seq\|histSeq\|orderId\|itemId\|accountId"
grep -rn "findBy.*mbrId\|findBy.*userId\|where.*mbrId\|where.*userId" src/ --include="*.java" --include="*.kt" --include="*.xml" -B 3 -A 3
grep -rn "userInfo\.mbrId\|userInfo\.userId\|session\.mbrId" src/ --include="*.java" --include="*.kt" -B 2 -A 5
grep -rn "@PostMapping\|@DeleteMapping\|@PutMapping" src/ --include="*.java" --include="*.kt" -B 5 | grep -B 4 "cancel\|delete\|remove\|update\|modify"
```

**판정 (자동스캔은 후보만 탐지, LLM이 아래 4조건 전체 충족 확인 후 확정)**:
1. 엔드포인트가 요청(path/body)으로 리소스 ID를 받는다
2. 서비스 레이어가 그 ID를 세션 ID(`userInfo.mbrId` 등)와 대조하지 않는다
3. DB 쿼리 `WHERE`절이 요청 ID를 직접 사용한다
4. 공격자가 다른 사용자의 ID로 치환 가능하다

취소/삭제 → **높음(4)** | 개인정보 포함 조회/수정 → **높음(4)** | 개인정보 미포함 조회 → **중간(3)**. category: `IDOR`, cwe_id: `CWE-639`.

### A-6. 세션/토큰 전달구조 분석 — 수동 심층진단 필수 (Auth 5-6)

```bash
grep -rn "getHeader\|x-.*session\|x-.*token\|Authorization\|addHeader" src/ --include="*.java" --include="*.kt" -i | grep -v "test\|Test" | head -30
grep -rn "session/info\|auth/validate\|token/verify\|checkSession\|validateToken" src/ --include="*.java" --include="*.kt" --include="*.properties" --include="*.yml" -n
grep -rn "HandlerMethodArgumentResolver\|resolveArgument\|@AuthenticationPrincipal" src/ --include="*.java" --include="*.kt" -A 10
grep -rn "loadUrl.*session\|loadUrl.*token\|redirectUrl.*session\|\"?session.*=.*getSession" src/ --include="*.java" --include="*.kt" --include="*.js" --include="*.ts" -n
grep -rn "internal\|sendError.*403\|FORBIDDEN\|/internal/" src/ --include="*.java" --include="*.kt" -B 2 -A 3
grep -rn "extraHeaders\|loadUrl.*header\|addJavascriptInterface\|evaluateJavascript" src/ --include="*.java" --include="*.kt" -B 2 -A 5
```

**판정**: 세션ID가 URL 파라미터에 노출 → **SESSION_TOKEN_EXPOSURE, 취약, Medium** (서버 로그·Referer 노출). Native App→Webview 헤더 주입 구조에서 TLS 미적용 구간 존재 → **SESSION_TOKEN_EXPOSURE, 취약, Medium**. Gateway가 `/internal/*` 경로를 외부 차단하지 않음 → **INTERNAL_API_EXPOSURE, 취약, High**.

---

## B. 접근제어/ACL

### B-1. Spring Security ACL 분석 (ACL 4-1)

```bash
find src -name "*SecurityConfig*" -o -name "*SecurityConfiguration*" -o -name "*WebSecurityConfig*" 2>/dev/null
grep -rn "antMatchers\|requestMatchers\|authorizeRequests\|authorizeHttpRequests" src/ --include="*.java" --include="*.kt" -A 5
grep -rn "hasIpAddress" src/ --include="*.java" --include="*.kt" -A 3
grep -rn "permitAll\(\)" src/ --include="*.java" --include="*.kt" -B 2 -A 1
grep -rn "csrf\(\)\|csrf\.disable\|CsrfConfigurer" src/ --include="*.java" --include="*.kt" -A 3
```

**판정**: 불필요하게 넓은 `permitAll()` 범위 → **BROKEN_ACCESS_CONTROL, 취약, High**. 근거 없는 `csrf().disable()`(stateless JWT REST API 등 문서화된 근거 없음) → **BROKEN_ACCESS_CONTROL, 취약, Medium**.

### B-2. 커스텀 @Acl 어노테이션 분석 (ACL 4-2)

```bash
grep -rn "@interface Acl\|annotation class Acl" src/ --include="*.java" --include="*.kt" -n
grep -rn "@Acl\|@PreAuthorize\|@Secured" src/ --include="*.java" --include="*.kt" -n
grep -rn "AclAdvisor\|@Aspect.*[Aa]cl\|@Around.*[Aa]cl\|Advisor" src/ --include="*.java" --include="*.kt" -A 10
grep -rn "@Acl(" src/ --include="*.java" --include="*.kt" -A 2
grep -rn "local\|dev\|test" src/ --include="*.java" --include="*.kt" -i | grep -i "acl\|skip\|bypass\|disable\|ignore"
grep -rn "profiles\|active\|environment" src/ --include="*.java" --include="*.kt" -A 5 | grep -B 3 "[Aa]cl"
```

**판정**: `local`/`dev` 프로파일에서 ACL 전체 비활성화 + 해당 서버가 외부 접근 가능 → **INTERNAL_API_EXPOSURE, 취약, High**.

### B-3. IP 기반 ACL 우회 — 수동 심층진단 필수 (ACL 4-3)

**Vuln 1 — Host Header Spoofing**
```bash
grep -rn "@Acl(host\|@Acl.*host\s*=" src/ --include="*.java" --include="*.kt" -A 2
grep -rn "getServerName\(\)" src/ --include="*.java" --include="*.kt" -B 5 -A 3
grep -rn "getHeader.*[Hh]ost\|\"Host\"\|'Host'" src/ --include="*.java" --include="*.kt" -B 3 -A 3
```
`request.getServerName()`(HTTP Host 헤더, 공격자 제어 가능) 단독으로 host 비교 → **IP_ACL_BYPASS, 취약, High**. 서버측 설정값(`serverProperties.getHostname()`) 사용 시 양호.

**Vuln 2 — contains() 부분 문자열 매칭**
```bash
grep -rn "\.contains(realIP\|\.contains(clientIp\|\.contains(remoteAddr\|allowedIP\.contains\|ipList\.contains" src/ --include="*.java" --include="*.kt" -B 3 -A 3
grep -rn "\.contains(" src/ --include="*.java" --include="*.kt" -B 2 -A 2 | grep -i "ip\|addr\|host\|allow"
```
`allowedIP.contains(realIP)`(콤마 구분 문자열에 대한 substring 매칭 — 예: `"10.0.0.1,10.0.0.2".contains("0.0")` = true) → **IP_ACL_BYPASS, 취약, High**. `.split(",")` + exact equals/`.contains(list)` 사용 시 양호.

**Vuln 3 — X-Forwarded-For 미처리**
```bash
grep -rn "getRemoteAddr\(\)\|X-Forwarded-For\|x-forwarded-for\|X-Real-IP" src/ --include="*.java" --include="*.kt" -B 3 -A 5
grep -rn "getHeader.*[Ff]orwarded\|getHeader.*X-Real\|RemoteIpFilter\|ForwardedHeaderFilter" src/ --include="*.java" --include="*.kt" -A 3
grep -rn "server\.forward-headers-strategy\|use-forward-headers\|remoteip\|proxy" . --include="*.properties" --include="*.yml" --include="*.yaml" -i -n
```
프록시/LB 환경에서 `getRemoteAddr()`만 사용(항상 프록시 IP 반환, ACL 무력화) → **IP_ACL_BYPASS, 취약, High**. `X-Forwarded-For`를 신뢰 프록시 검증 없이 그대로 신뢰 → **IP_ACL_BYPASS, 취약, High**.

### B-4. 전체 ACL 커버리지 감사 (ACL 4-4)

```bash
grep -rn "@Acl(" src/ --include="*.java" --include="*.kt" -A 2
grep -rn "@RestController\|@Controller" src/ --include="*.java" --include="*.kt" -l | xargs grep -L "@Acl\|@PreAuthorize\|@Secured" 2>/dev/null
grep -rn "@PostMapping\|@GetMapping\|@RequestMapping" src/ --include="*.java" --include="*.kt" -B 5 | grep -B 4 "batch\|admin\|internal\|system\|settle\|cron" | grep -v "@Acl\|@PreAuthorize"
grep -rn "@Session\|@Acl" src/ --include="*.java" --include="*.kt" -n | awk -F: '{print $1}' | sort | uniq -c | sort -rn
```

내부/배치/관리자 API 중 `@Acl`과 `@Session`/`@PreAuthorize` 모두 없음 → **INTERNAL_API_EXPOSURE, 취약, High**. `@Acl`은 있으나 `HttpServletRequest` 파라미터 누락(AOP가 인터셉트 불가) → **INTERNAL_API_EXPOSURE, 취약, High**. 이 항목은 표 전체를 `review_note`에 `## 무인증/무ACL 배치·관리자 엔드포인트 목록` 섹션으로 작성(RULE-4).

---

## C. TOCTOU/동시성

### C-1. 핵심 API 식별 (Race STEP 1)

```bash
grep -rn "@PostMapping\|@PutMapping\|@DeleteMapping" src/ --include="*.kt" --include="*.java" | grep -i "purchase\|buy\|cancel\|refund\|issue\|point\|coupon\|payment\|order\|charge"
grep -rn "@GetMapping" src/ --include="*.kt" --include="*.java" | grep -i "apply\|register\|confirm\|execute\|process"
```
이후 C-2~C-7을 식별된 각 엔드포인트에 순서대로 적용한다.

### C-2. @Transactional 범위 분석 (Race STEP 2, P1/P3)

```bash
grep -rn "fun " src/ --include="*.kt" -A 5 | grep -v "@Transactional" | grep "repository\.save\|repository\.delete\|repository\.update\|\.save(\|\.delete("
grep -rn "Propagation.REQUIRES_NEW\|propagation = Propagation" src/ --include="*.kt" --include="*.java"
```
`@Transactional` 없이 검증(SELECT)+실행(INSERT/UPDATE)이 한 메서드에 존재 → **RACE_CONDITION(P1), 취약, High**. 외부 메서드 `@Transactional` 없음 + 내부만 `REQUIRES_NEW` → **RACE_CONDITION(P3), 취약, High** — 수동 심층진단 필요(RULE-2).

### C-3. SELECT-then-Act 패턴 (Race STEP 3, P2/P4)

```bash
grep -rn "fun has\|fun exists\|fun check\|fun validate\|fun verify\|fun isValid\|fun isDuplicate" src/ --include="*.kt" --include="*.java"
grep -rn "\.count()\|\.exists()\|countBy\|existsBy\|SELECT COUNT" src/ --include="*.kt" --include="*.java" --include="*.xml"
grep -rn "findBy\|findAll\|selectBy" src/ --include="*.kt" --include="*.java" -A 10 | grep "\.save(\|\.insert\|\.update\|repository\."
```
count/exists 체크 후 INSERT, 원자성 보장 없고 UNIQUE CONSTRAINT도 없음 → **RACE_CONDITION(P4), 취약, High**. `@Transactional`이 있어도 SELECT에 `FOR UPDATE` 없으면 동시 읽기 허용 상태 — C-4로 확인 후 **RACE_CONDITION(P2), 취약, 중간~높음** — 수동 심층진단 필요(RULE-2).

### C-4. SELECT FOR UPDATE 사용 여부 (Race STEP 4)

```bash
grep -rn "@Lock\|LockModeType\|PESSIMISTIC_WRITE\|PESSIMISTIC_READ" src/ --include="*.kt" --include="*.java"
grep -rn "FOR UPDATE\|for update\|NOWAIT\|SKIP LOCKED" src/ --include="*.kt" --include="*.java" --include="*.xml" --include="*.sql"
grep -rn "@Query" src/ --include="*.kt" --include="*.java" -A 3 | grep -i "for update\|pessimistic"
```
동시 요청이 같은 행을 검증 후 수정하는데 FOR UPDATE/분산락/UNIQUE CONSTRAINT 전부 부재 → C-2/C-3 판정에 반영.

### C-5. 예외 묵살 패턴 (Race STEP 5, P5/P8)

```bash
grep -rn "catch" src/ --include="*.kt" --include="*.java" -A 3 | grep -v "throw\|rethrow\|log\.\|logger\." | grep "}"
grep -rn "} catch\|} finally" src/ --include="*.kt" --include="*.java" -B 2 -A 5
grep -rn "fun cancel\|fun refund\|fun rollback\|fun revert" src/ --include="*.kt" --include="*.java" -A 30 | grep -B 5 "restTemplate\|WebClient\|feignClient\|\.call(\|\.send("
grep -rn "} catch\|} finally" src/ --include="*.kt" --include="*.java" -B 2 -A 8 | grep -B 5 "externalApi\|restTemplate\|\.call(\|paymentApi\|pointApi"
```
`catch` 블록에 `throw`/`return` 없이 후속 로직 계속 실행 → **RACE_CONDITION(P5), 취약, Medium**. 외부 API(결제/포인트) 호출이 `@Transactional` 없는 취소/환불 메서드에서 DB 저장과 혼재(외부 API는 롤백 불가) → **RACE_CONDITION(P8), 취약, High** — 수동 심층진단 필요(RULE-2). `catch`+`finally`에서 동일 외부 API 이중 호출 → **RACE_CONDITION(P8), 취약, High**.

### C-6. 배치/정산 API 동시성 제어 (Race STEP 6, P7/P9)

```bash
grep -rn "@Scheduled\|@PostMapping\|@GetMapping" src/ --include="*.kt" --include="*.java" | grep -i "batch\|settlement\|schedule\|process\|execute\|job"
grep -rn "forEach\|for (\|\.map {" src/ --include="*.kt" --include="*.java" -B 5 | grep -v "@Transactional" | grep "repository\.\|service\."
grep -rn "redisService\.\|redisTemplate\.\|RedisTemplate" src/ --include="*.kt" --include="*.java" | grep -i "put\|set\|get\|exists\|lock"
grep -rn "fun process\|fun execute\|fun settle\|fun batch" src/ --include="*.kt" --include="*.java" -B 5 | grep -v "@Transactional" | grep "fun "
grep -rn "REQUIRES_NEW" src/ --include="*.kt" --include="*.java" -B 10 | grep -v "@Transactional"
grep -rn "fun.*[Bb]atch\|fun.*[Ss]ettle" src/ --include="*.kt" --include="*.java" -A 5 | grep "redis\|lock\|setnx\|tryLock"
grep -rn "@PostMapping\|@GetMapping" src/ --include="*.kt" -B 5 | grep -i "batch\|settle\|process" | grep -v "@Acl\|@Session\|@Lock"
```
배치 `@Transactional` 없는 `forEach`/`map` 반복 처리(건당 원자성 보장 없음) → **RACE_CONDITION(P7), 취약, High**. Redis 기록만 있고 get→check 가드 없음(중복 방지 효과 없음) → **RACE_CONDITION(P6), 취약, Medium** — 수동 심층진단 필요(RULE-2). 배치 최상위 `@Transactional` 없음 + 내부만 `REQUIRES_NEW` + 분산 락 없음(처리 전 상태 선점 없음) → **RACE_CONDITION(P9), 취약, High** — 수동 심층진단 필요(RULE-2).

### C-7. DB 수준 안전장치 확인 (Race STEP 7)

```bash
grep -rn "@UniqueConstraint\|@Column(unique\|UNIQUE INDEX\|unique = true" src/ --include="*.kt" --include="*.java" --include="*.xml"
grep -rn "@Version" src/ --include="*.kt" --include="*.java"
```
UNIQUE CONSTRAINT/`@Version`/FOR UPDATE/분산락 중 무엇도 없는 경우 C-2~C-6 판정을 확정한다. 하나라도 있으면 해당 안전장치가 실질적 가드로 동작하는지(예외 처리 유무, get→check 순서) 확인 후 완화 여부를 `manual_review_note`에 기록한다.

---

### ⚠️ 완료 조건 자가 검증 (필수 — 미충족 시 Task 미완료)

```
□ A-5 IDOR / C-2~C-7 RACE_CONDITION 후보 전건에 대해 Read 툴로 코드 직접 확인 완료
  - 미확인 상태로 needs_review: true 유지한 채 finding 생성 금지 (RULE-1)

□ 자동탐지 불가 항목(RULE-2) 전체 수동 확인 완료
  - Auth 5-6, ACL 4-3 Vuln1/Vuln3, Race P2/P3/P6/P8/P9 각각 grep 절차 실행 후 판정 기재

□ B-4 전체 ACL 커버리지 감사 결과 review_note에 마크다운 테이블 섹션(RULE-4) 작성

□ IP 관련 evidence.code_snippet 전체 [REDACTED_IP] 마스킹 확인 (RULE-3)

□ JWT/CORS/DTO 관련 코드 발견 시 finding 미생성, sec-scan-data 경계 노트만 기재 확인

□ findings 배열이 비어 있지 않은 경우 각 finding에 evidence.file(실제 경로) 기재 필수
```

---

### 판정 기준

| 심각도 | 조건 |
|---|---|
| **Critical** | 전역 인증 강제 완전 부재, 결제/취소 API @Session 누락, 테스트 세션 우회 비게이팅, 인증서버 Fail-Open, 배치/관리자 API 무인증+무ACL |
| **High** | IDOR(취소/삭제/개인정보), PIN 재검증 누락, IP ACL 우회(Host spoofing/contains 부분매칭/XFF 미처리), 내부 API @Acl 누락, RACE_CONDITION P1/P3/P4/P7/P8/P9 |
| **Medium** | `anyRequest().permitAll()` 단일방어선, ACL local/dev 비활성화(외부 비접근 서버), csrf 근거불명 비활성화, 세션 URL노출, RACE_CONDITION P2/P5/P6 |
| **Low** | IDOR(개인정보 미포함 조회), 과도한 permitAll() 범위 |
| **Info** | 세션/토큰 전달구조 분류 참고사항, DB 안전장치 부분 적용 |

---

### 출력 형식

> **`affected_endpoints` 작성 규칙 (전체 Task 공통)**: `shared/references/task_prompts/task_25_data_protection.md`의 규칙과 동일 — `method`/`path`(필수)/`controller`/`description` 필드. 전역 영향은 `"path": "전역 (전체 API)"` 1건 기재.

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
      "manual_review_note": "OrderService.cancel() 내부에서 userInfo.mbrId 대조 로직 부재 확인.",
      "recommendation": "1. WHERE 절의 mbrId를 요청 파라미터 대신 세션의 userInfo.mbrId로 교체.\n2. 서비스 레이어 진입 시 requestMbrId == sessionMbrId 검증 추가."
    }
  ],
  "auth_access_assessment": {
    "global_auth_enforcement": "spring_security | aop_annotation | interceptor | none",
    "test_session_bypass_gated": true,
    "acl_env_bypass": false,
    "idor_candidates_confirmed": 1,
    "idor_candidates_fp": 2,
    "race_condition_candidates_confirmed": 0,
    "race_condition_candidates_fp": 0
  },
  "consolidation_note": "자동스캔 후보 N건 중 IDOR M건/RACE_CONDITION K건 코드 확인 후 확정. 원본은 state/<prefix>/task26_result.json 보존.",
  "executed_at": "",
  "claude_session": ""
}
```

**ID 명명 규칙:**
- `AUTH-IDOR-NNN` — IDOR 확정 건
- `AUTH-PRIV-NNN` — PRIVILEGE_ESCALATION (배치/관리자 인증 누락)
- `AUTH-BYP-NNN` — AUTH_BYPASS (전역 인증우회/Fail-Open/테스트세션)
- `AUTH-PIN-NNN` — PIN_REVERIFICATION_MISSING
- `AUTH-SESS-NNN` — SESSION_TOKEN_EXPOSURE
- `AUTH-BAC-NNN` — BROKEN_ACCESS_CONTROL (permitAll/CSRF)
- `AUTH-IPACL-NNN` — IP_ACL_BYPASS
- `AUTH-IAE-NNN` — INTERNAL_API_EXPOSURE
- `AUTH-RACE-NNN` — RACE_CONDITION

**주의**:
- 원본 자동스캔 JSON(`state/<prefix>/task26_result.json`)은 수정하지 않는다. 증적 보존용.
- 확정/보완 findings는 모두 이 LLM 파일(`state/<prefix>/task26_llm.json`)에만 작성한다.

---

### 금지사항
- 추측 금지 (코드 근거 필수)
- 민감정보(세션ID/토큰/내부 IP/PII) 원문 포함 금지 → RULE-3 마스킹 규칙 적용
- 자동 스캔 결과를 번복할 때는 코드 근거 명시 필수
- 스크립트가 이미 판정한 "양호" 항목은 재검토 불필요
- JWT/CORS/DTO 영역 finding 생성 금지 (sec-scan-data 소관)

---

### 코드 증적 품질 기준 (필수 준수)

> ⚠️ **evidence.file은 반드시 실제 파일 경로여야 한다. evidence.code_snippet은 반드시 Read 툴로 읽은 실제 파일 내용을 사용한다.**

- `evidence.file`: repo root 기준 전체 상대경로 필수
- `evidence.code_snippet`: Read 툴로 직접 읽은 실제 코드만 허용
- 파일을 직접 읽지 못한 경우: `needs_review: true` + `manual_review_note: "코드 미확인"` 표시

---

## findings_AUTH.json 생성 (LLM-Check Phase 최종 출력)

LLM-Check Phase 완료 후 `state/<prefix>/findings_AUTH.json`을 생성한다.

### 절차

1. `state/<prefix>/task26_result.json`의 `auto_findings[]` 로드
2. 각 항목 LLM 교차검증 수행:
   - **FP 판정**: `findings[]`에서 제거, `evidence_trail[]`에 `fp_corrected: true`로 기록
   - **TP 확정**: description, code_snippet, evidence 보강 (IDOR/RACE_CONDITION 후보는 RULE-1 절차로 코드 직접 확인)
3. Auto-Scan 미탐지 취약점(FN) 발견 시 신규 finding 추가: `fn_detected: true`, `source: "llm-check(fn-detected)"`
4. finding_id 재부여: `AUTH-001` 순번 (심각도 내림차순)
5. `state/<prefix>/findings_AUTH.json` 저장

### 출력 스키마 (shared/references/output_schemas.md 참조)

```json
{
  "task_id": "auth",
  "generated_at": "ISO8601",
  "scan_coverage": {
    "fn_disclaimer": "Auto-Scan은 정적 패턴 기반이므로 흐름 분석이 필요한 FOR UPDATE 부재(P2)/REQUIRES_NEW 단독(P3,P9)/Redis 가드부재(P6)/보상트랜잭션 미구현(P8), Host Header Spoofing(ACL 4-3 Vuln1), 세션/토큰 전달구조(Auth 5-6)는 후보 탐지 정확도가 낮아 LLM 수동 심층진단으로 보완함"
  },
  "summary": { "total": 0, "취약": 0, "정보": 0, "fn_detected": 0 },
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
