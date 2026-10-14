# 인증/인가 진단 방법론 (Auth 5-1 ~ 5-6 + 사례/체크리스트)

> **이 파일의 위치와 우선순위**
> - 이 파일은 원본 진단 방법론을 **원문 그대로 보존**한 참조 자료다 (라인 단위 복사, 고객사 식별정보만 익명화).
> - 실행 절차·판정 심각도·출력 형식은 `references/task_prompts/task_26_auth_review.md`가 **우선**한다.
> - 원본의 "Output language", "Final Verdict Summary Table", "Finding Report Format" 지시는
>   task_26 「원본 방법론 출력 지시 매핑」 규칙에 따라 `task26_llm.json` / `summary_auth.md` / `dast_candidates_AUTH.json`으로 매핑된다.
> - 원본 사례(파일명·클래스명·IP·헤더명)는 익명화 예시다. 실제 진단 대상의 이름으로 간주하지 말 것.

> task_26 연결: Section A (A-1 ~ A-7), Section E (DAST 후보)
> 원본 메타: 분석 대상: [익명화] 고객사 Webview API 서비스 (Spring Boot + Kotlin) / 작성일 2026-03-27

## Part A — PHASE 5 구조화 절차 (Auth_Analysis)

> 📎 원본: `MySkills/Auth_Analysis.md` L1-372 (원문 보존, 익명화 적용)

### Authentication & Authorization Analysis

> **Output language: Korean**
>
> Analyze the source code directly to detect authentication and authorization vulnerabilities and report all findings in the format specified below.
> If no vulnerability is found for a given item, record "이상 없음" (No issue found).
> Perform each step of PHASE 5 in order, then produce the Final Verdict Summary Table at the end.
>
> **Scope:** Application-layer authentication and authorization logic only.
> IP-based ACL bypass → ACL_Analysis.md | Race Condition → RACE_CONDITION_ANALYSIS.md | Hardcoded credentials → DataProtection_Analysis.md

---

#### PHASE 5. Authentication & Authorization

##### 5-1. Authentication Mechanism Discovery

**Target:** Entire source tree — security config, custom annotations, AOP

```bash
# Find all custom annotations
grep -rn "@interface\|annotation class" src/ --include="*.java" --include="*.kt" -n

# Find AOP Aspects and Advisors
grep -rn "@Aspect\|@Before\|@Around\|@After\|Advisor" src/ --include="*.java" --include="*.kt" -B 1 -A 5

# Check global authentication enforcement via Spring Security
grep -rn "SecurityFilterChain\|WebSecurityConfigurerAdapter\|@EnableWebSecurity" \
     src/ --include="*.java" --include="*.kt" -l

# Check global enforcement via Interceptor
grep -rn "addInterceptors\|HandlerInterceptor\|InterceptorRegistry" \
     src/ --include="*.java" --include="*.kt" -A 10

# Check AOP Pointcut scope (class-level vs parameter-level annotation)
grep -rn "@Pointcut\|execution(" src/ --include="*.java" --include="*.kt" -A 3

# anyRequest().permitAll() 단일 방어선 구조 확인
grep -rn "anyRequest().*permitAll()\|anyRequest\(\)\.permitAll\|anyRequest\(\)\s*\.\s*permitAll" \
     src/ --include="*.java" --include="*.kt" -B 5 -A 2
```

Analysis Instructions:
- Identify all custom authentication/authorization annotations (e.g., `@Session`, `@LoginUser`, `@Auth`)
- Locate the AOP Advisor/Aspect that processes each annotation and understand its enforcement logic
- Classify the global authentication enforcement type and record the associated risk:

```
| 인증 강제 유형 | 위험 수준 |
|--------------|---------|
| Spring Security authorizeRequests() 전역 설정 | 낮음 — Whitelist 기반, 누락 경로 = 거부 |
| AOP + 파라미터 어노테이션 방식 | 높음 — 어노테이션 누락 = 인증 없음 |
| Interceptor 방식 | 중간 — excludePathPatterns 별도 확인 필요 |
| 전역 강제 없음 | 치명 — 모든 엔드포인트 개별 확인 필요 |
```

- Identify the AOP Pointcut scope:
  - **Class-level**: annotation on the class applies to all methods — missing class annotation = no auth on entire controller
  - **Parameter-level**: annotation declared per parameter — missing on one parameter = no auth on that method only
- `anyRequest().permitAll()` 패턴 확인:
  - Spring Security `authorizeHttpRequests` 블록에서 `anyRequest().permitAll()`이 사용되면 Spring Security 인가 레이어가 무력화됨 → JWT 커스텀 필터 등 단일 방어선에만 의존하는 구조
  - 커스텀 필터가 우회되면 전체 보호가 붕괴됨 → **취약** (중간 심각도)
  - 올바른 패턴: `requestMatchers(whitelist).permitAll().anyRequest().authenticated()`

---

##### 5-2. @Session Annotation Analysis

**Target:** Entire source tree

```bash
# Full scan of @Session usages and required values
grep -rn "@Session" src/ --include="*.java" --include="*.kt" -n
grep -rn "@Session" src/ --include="*.java" --include="*.kt" | grep "required\s*=\s*false\|required\s*=\s*true"

# Find payment / cancel / sensitive APIs with required=false or missing @Session
grep -rn "@PostMapping\|@PutMapping\|@DeleteMapping" src/ --include="*.java" --include="*.kt" \
     | grep -i "pay\|purchase\|cancel\|batch\|admin\|settle\|order\|refund"

# Detect test session ID bypass patterns
grep -rn "TEST_ID\|startsWith.*ID\|mock.*session\|testSession\|TEST_SESSION" \
     src/ --include="*.java" --include="*.kt" -A 5

# Verify whether test session bypass is gated to dev/local environment only
grep -rn "TEST_ID\|startsWith.*ID" src/ --include="*.java" --include="*.kt" -A 10 \
     | grep -i "active\|profile\|env\|local\|dev"

# Detect Fail-Open: authentication passes on timeout/error
grep -rn "timeout\|fallback\|catch.*[Ss]ession\|null.*UserInfo\|InvalidSession\|catch.*[Aa]uth" \
     src/ --include="*.java" --include="*.kt" -A 5

# 서비스 레이어 내 환경 프로파일 기반 인증 우회 패턴 확인
grep -rn "acceptsProfiles\|getActiveProfiles\|activeProfiles" \
     src/ --include="*.java" --include="*.kt" -B 5 -A 10
```

Analysis Instructions:
- Enumerate all `@Session` usages and classify by `required` value:
  - `required = true` → access blocked without session — **safe**
  - `required = false` → unauthenticated access allowed — verify whether the endpoint requires authentication by business logic
  - Missing `required` attribute → check default value in annotation definition
- Flag any payment, purchase, cancel, or settle API that has `required = false` or is missing `@Session` entirely
- Check for test session ID bypass patterns (e.g., `sessionId.startsWith("TEST_ID:")`):
  - If the bypass is active in non-`local`/`dev` environments → **Vulnerable** (attacker can impersonate any user)
- Check external authentication server timeout handling:
  - Timeout → authentication passes (Fail-Open) → **Vulnerable**
  - Timeout → exception thrown (Fail-Closed) → **Safe**
  - Timeout → `null` UserInfo passed through → **Vulnerable** (NullPointerException or unauthenticated continuation)
- **서비스 레이어 환경별 인증 우회 패턴:**
  - `!env.acceptsProfiles("prod")` 등의 조건으로 인증 서버 응답 코드를 강제 성공 처리하는 패턴 → **취약 (Fail-Open)**
  - JWT 시크릿이 전 환경 동일한 경우: dev 환경에서 발급한 토큰이 prod API에서도 유효 → **연계 위험 (높음)** — 반드시 함께 보고할 것

---

##### 5-3. Batch / Admin API Authentication Coverage

**Target:** Controllers with batch, admin, internal, system, cron, settle patterns

```bash
# Find batch / admin / internal controllers
find src/ -name "*Batch*Controller*" -o -name "*Admin*Controller*" \
          -o -name "*Internal*Controller*" -o -name "*Manage*Controller*" 2>/dev/null

# Find endpoints missing @Session annotation
grep -rn "@PostMapping\|@GetMapping\|@PutMapping\|@DeleteMapping\|@RequestMapping" \
     src/ --include="*.java" --include="*.kt" -B 10 \
     | grep -B 9 "batch\|admin\|internal\|system\|settle\|cron" \
     | grep -v "@Session\|@PreAuthorize\|@Secured"

# Find controllers with no authentication annotation at all
grep -rn "@RestController\|@Controller" src/ --include="*.java" --include="*.kt" -l \
     | xargs grep -L "@Session\|@PreAuthorize\|@Secured\|@LoginUser" 2>/dev/null
```

Analysis Instructions:
- For each batch/admin/internal controller found, verify whether every endpoint has `@Session` (or equivalent authentication annotation)
- **Missing `@Session` and missing `@Acl`** → unauthenticated access possible from any source → **Vulnerable**
- **Missing `@Session` but `@Acl` present** → IP-restricted but unauthenticated — check whether IP ACL is correctly enforced (see ACL_Analysis.md 4-3)
- Produce a summary table:

```
| Controller | Endpoint | @Session | @Acl | 판정 |
|-----------|----------|----------|------|------|
| BatchController | POST /batch/update | ✗ | ✗ | 취약 — 무인증 접근 가능 |
| AdminController | GET /admin/users | ✓ | ✓ | 양호 |
| InternalController | POST /internal/sync | ✗ | ✓ (ip) | 확인 필요 — IP ACL만 존재 |
```

---

##### 5-4. PIN / Password Server-Side Verification

**Target:** Payment, purchase, and high-privilege action controllers

```bash
# Find PIN / password confirmation fields in session/UserInfo objects
grep -rn "pinConfirmationDate\|passwordConfirmationDate\|pinStatus\|pinVerified\|pinTime" \
     src/ --include="*.java" --include="*.kt" -n

# Find payment / purchase controllers and check PIN verification logic
grep -rn "pinConfirmationDate\|passwordConfirmationDate" \
     src/ --include="*.java" --include="*.kt" -B 3 -A 10

# Find payment APIs that do NOT reference pinConfirmationDate
grep -rn "class.*Pay.*Controller\|class.*Purchase.*Controller\|class.*Order.*Controller" \
     src/ --include="*.java" --include="*.kt" -l \
     | xargs grep -L "pinConfirmationDate\|passwordConfirmationDate" 2>/dev/null

# Check whether Request DTO for payment APIs contains a PIN/password field
grep -rn "class.*Request\|data class.*Request" src/ --include="*.java" --include="*.kt" \
     | grep -i "pay\|purchase\|order\|join" \
     | awk -F: '{print $1}' | sort -u \
     | xargs grep -l "pin\|password\|secret" 2>/dev/null
```

Analysis Instructions:
- Identify all APIs that require PIN or password confirmation before execution (payment, high-value actions, account changes)
- Verify that the server checks `pinConfirmationDate` (or equivalent) against the current timestamp:
  - **Safe pattern**: `pinConfirmationDate` is checked within a time window (e.g., within 10 seconds)
  - **Vulnerable pattern**: no `pinConfirmationDate` check — PIN is only enforced at the UI level
- If the Request DTO for a payment/purchase API has **no PIN/password field at all** → UI-only enforcement → direct API call bypasses PIN entirely → **Vulnerable**

```kotlin
// Safe — server-side PIN time verification
val pinTimeDiff = if (userInfo.pinConfirmationDate != null)
    (Math.abs(System.currentTimeMillis() - userInfo.pinConfirmationDate) / 1000).toInt()
else -1
if (pinTimeDiff == -1 || pinTimeDiff > 10) throw PinConfirmationException()

// Vulnerable — no PIN verification; UI enforces it, server does not
fun joinPurchase(@RequestBody req: PurchaseRequest, userInfo: UserInfo) {
    // pinConfirmationDate not checked here
    purchaseService.join(req, userInfo)
}
```

---

##### 5-5. IDOR (Insecure Direct Object Reference)

**Target:** Controllers that accept resource identifiers (mbrId, userId, seq, histSeq) as parameters

```bash
# Find endpoints accepting resource ID parameters (PathVariable / RequestParam)
grep -rn "@PathVariable\|@RequestParam" src/ --include="*.java" --include="*.kt" \
     | grep -i "mbrId\|userId\|seq\|histSeq\|orderId\|itemId\|accountId"

# Find service methods that query DB using request-supplied ID (not session ID)
grep -rn "findBy.*mbrId\|findBy.*userId\|where.*mbrId\|where.*userId" \
     src/ --include="*.java" --include="*.kt" --include="*.xml" -B 3 -A 3

# Check whether ownership is verified (session ID compared against request ID)
grep -rn "userInfo\.mbrId\|userInfo\.userId\|session\.mbrId" \
     src/ --include="*.java" --include="*.kt" -B 2 -A 5

# Find cancel / delete / modify APIs that take a resource ID parameter
grep -rn "@PostMapping\|@DeleteMapping\|@PutMapping" src/ --include="*.java" --include="*.kt" \
     -B 5 | grep -B 4 "cancel\|delete\|remove\|update\|modify"
```

Analysis Instructions:
- For each endpoint that accepts a resource identifier (`mbrId`, `userId`, `orderId`, etc.) as a path variable or request parameter:
  1. Does the service layer compare the supplied ID against the session's `userInfo.mbrId` / `userInfo.userId`?
  2. If not, does the DB query's `WHERE` clause use the **session** ID or the **request** ID?
- **Vulnerable**: `WHERE user_id = :requestMbrId` — attacker supplies another user's ID → other user's data accessed/modified
- **Safe**: `WHERE user_id = :sessionMbrId` — always scoped to the authenticated user

IDOR risk classification:

```
| 작업 유형 | 위험도 |
|----------|--------|
| 취소 / 삭제 | 높음 — 타인 데이터 파괴 |
| 개인정보 포함 조회 | 높음 — 프라이버시 침해 |
| 수정 / 변경 | 높음 — 데이터 위변조 |
| 개인정보 미포함 조회 | 중간 — 데이터 열람 |
```

IDOR confirmed when ALL of the following apply:
1. Endpoint accepts a user/resource ID from the request (path variable or request body)
2. Service layer does not compare the supplied ID against the session ID
3. DB query uses the request-supplied ID directly in the `WHERE` clause
4. Attacker can substitute another user's ID in the request

---

##### 5-6. Session / Token Delivery Architecture Analysis

**Target:** Security config, filters, gateway configuration, interceptors

```bash
# Identify the auth header key name used
grep -rn "getHeader\|x-.*session\|x-.*token\|Authorization\|addHeader" \
     src/ --include="*.java" --include="*.kt" -i | grep -v "test\|Test" | head -30

# Find external authentication server call URL
grep -rn "session/info\|auth/validate\|token/verify\|checkSession\|validateToken" \
     src/ --include="*.java" --include="*.kt" --include="*.properties" --include="*.yml" -n

# Find UserInfo injection method
grep -rn "HandlerMethodArgumentResolver\|resolveArgument\|@AuthenticationPrincipal" \
     src/ --include="*.java" --include="*.kt" -A 10

# Check whether session ID appears in URL parameters (log/Referer exposure risk)
grep -rn "loadUrl.*session\|loadUrl.*token\|redirectUrl.*session\|\"?session.*=.*getSession" \
     src/ --include="*.java" --include="*.kt" --include="*.js" --include="*.ts" -n

# Check Gateway / Zuul filter: internal path blocking
grep -rn "internal\|sendError.*403\|FORBIDDEN\|/internal/" \
     src/ --include="*.java" --include="*.kt" -B 2 -A 3

# Check whether session ID is passed via HTTP header injection into Webview
grep -rn "extraHeaders\|loadUrl.*header\|addJavascriptInterface\|evaluateJavascript" \
     src/ --include="*.java" --include="*.kt" -B 2 -A 5
```

Analysis Instructions:
- Identify the session/token delivery mechanism and report the header key name
- Classify the authentication architecture type and flag applicable risks:

```
| 유형 | 설명 | 주요 위험 |
|------|------|----------|
| Stateless (JWT) | 서버가 토큰 로컬 파싱 | 알고리즘 혼동, 만료 토큰 미검증 |
| Stateful (세션ID → 외부 서버) | 매 요청마다 인증 서버 호출 | 타임아웃 Fail-Open, SSRF |
| Native App → Webview 헤더 주입 | 앱이 세션ID를 HTTP 헤더에 삽입 | TLS 미적용 시 헤더 탈취/위변조 |
| 쿠키 기반 | 브라우저 자동 전송 | CSRF, Secure/HttpOnly 플래그 미설정 |
| URL 파라미터 포함 | 세션ID가 URL에 노출 | 서버 로그·Referer 헤더에 세션 노출 |
```

- Verify the following for Native App + Webview architectures:
  - Is the session injected via HTTP header? → Confirm TLS is enforced end-to-end
  - Does the Gateway/Zuul filter block direct access to `/internal/*` paths from external clients?
  - Is the session ID passed as a URL parameter? → **Vulnerable** (exposed in server logs and Referer headers)

> **Native App + Webview 구조가 확인된 경우**, 앱 클라이언트 측 토큰 저장 방식·전달 방식 5종·시나리오별 취약점 등 심층 점검을 위해 `WEBVIEW_SESSION_ANALYSIS.md`를 추가로 실행한다.

---

#### Final Verdict Summary Table

After completing the analysis, fill in the table below and include it in the report.

| Vulnerability | Safe | Vulnerable |
|--------------|------|-----------|
| 인증 강제 유형 | Spring Security 전역 설정 (Whitelist 기반) | AOP 어노테이션 방식에서 어노테이션 누락; 또는 전역 강제 없음 |
| AOP Pointcut 범위 | 클래스 레벨 어노테이션으로 전체 적용 | 파라미터 레벨에서 어노테이션 누락 시 해당 메서드 인증 미적용 |
| @Session required=false | 비로그인이 허용되는 공개 API에만 적용 | 결제·취소·민감 API에 required=false 또는 @Session 누락 |
| 테스트 세션 우회 (TEST_ID 등) | local/dev 환경에서만 동작, 운영 환경에서 비활성화 | 비개발 환경에서도 동작 → 임의 사용자 사칭 가능 |
| 인증 서버 Fail-Open | 타임아웃 → 예외 throw (Fail-Closed) | 타임아웃 → 인증 통과 또는 null UserInfo로 진행; 서비스 레이어 내 환경별 강제 성공 처리 |
| `anyRequest().permitAll()` 단일 방어선 | `requestMatchers(whitelist).permitAll().anyRequest().authenticated()` 구성 | `anyRequest().permitAll()` → Spring Security 인가 레이어 무효화; 커스텀 필터 단독 의존 구조 |
| 배치/관리 API 인증 | @Session + @Acl 모두 적용 | @Session 없음 + @Acl 없음 → 무인증 접근 가능 |
| PIN 서버 검증 | pinConfirmationDate 타임스탬프를 서버에서 재검증 | 서버 검증 없음; Request DTO에 PIN 필드 없음 → UI 레벨만 강제 |
| IDOR | DB WHERE 절이 세션 ID 사용 (sessionMbrId) | DB WHERE 절이 요청 바디 ID 사용 (requestMbrId) → 타인 리소스 접근 |
| IDOR 위험도 — 취소/삭제 | 소유권 검증 후 처리 | 소유권 미검증 → 타인 데이터 파괴 가능 |
| IDOR 위험도 — 개인정보 조회 | 세션 ID 기반 조회 | 파라미터 ID 기반 조회 → 타인 개인정보 열람 가능 |
| 세션 URL 노출 | 세션ID/토큰이 HTTP 헤더 또는 쿠키로만 전달 | 세션ID가 URL 파라미터에 포함 → 서버 로그·Referer 노출 |
| Webview 헤더 주입 | TLS 적용, Gateway에서 내부 헤더 외부 주입 차단 | TLS 미적용 구간 존재; 또는 외부에서 내부 헤더 덮어쓰기 가능 |

---

#### Finding Report Format

Write a separate entry in the format below for each vulnerability found.
If no vulnerability is found, state "인증/인가 취약점 없음".

```
파일 및 위치 (라인 번호):
  예) SampleGroupBuyController.kt (92번째 줄)
  예) SessionArgumentResolver.kt (45번째 줄)

취약 코드 샘플:
  예) // @Session 없이 결제 API 노출
      @PostMapping("/purchase/join")
      fun joinPurchase(@RequestBody req: PurchaseRequest): ResponseEntity<Unit> { ... }

  예) // 인증 서버 타임아웃 시 인증 통과 (Fail-Open)
      } catch (e: TimeoutException) {
          return null  // null UserInfo로 진행 → 무인증 처리
      }

취약점 근거:
  예) [세션 검증 누락] 결제 API에 @Session 어노테이션이 없어 세션 없이
      직접 API 호출이 가능함.

  예) [PIN 검증 미흡] 서버에서 pinConfirmationDate 타임스탬프를 검증하지 않아
      UI에서 PIN 입력을 강제하더라도 API 직접 호출로 우회 가능함.

  예) [IDOR] 서비스 레이어에서 요청 바디의 mbrId를 세션과 비교하지 않고
      DB 쿼리에 그대로 사용하여 타인의 리소스에 접근 가능함.

  예) [테스트 세션 우회] TEST_ID: prefix를 사용한 세션 우회 로직이
      운영 환경에서도 비활성화되지 않아 임의 사용자 사칭이 가능함.

개선 방안 (수정 코드 예시 포함):
  예) [세션 검증 누락] 모든 결제 API에 @Session(required = true) 추가.

  예) [PIN 검증 미흡]
      val pinTimeDiff = if (userInfo.pinConfirmationDate != null)
          (Math.abs(System.currentTimeMillis() - userInfo.pinConfirmationDate) / 1000).toInt()
      else -1
      if (pinTimeDiff == -1 || pinTimeDiff > 10) throw PinConfirmationException()

  예) [IDOR] WHERE 절의 mbrId를 요청 바디 값 대신 세션 값으로 교체.
      // 취약: WHERE member_id = :requestMbrId
      // 수정: WHERE member_id = :sessionMbrId (userInfo.mbrId 사용)

  예) [테스트 세션 우회] TEST_ID 분기를 local/dev 프로파일에서만 활성화하도록 제한.
      if ("local" == activeProfile || "dev" == activeProfile) { ... }
      또는 해당 코드 블록을 운영 배포 전 완전히 제거.
```


## Part B — 인증/인가 분석 방법론 보충 (AUTH_VULN_ANALYSIS)

> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L1-7 (원문 보존, 익명화 적용)

### 인증/인가 취약점 분석 방법론 (Spring Boot / Kotlin 기반 서비스)

> 작성일: 2026-03-27
> 분석 대상: [익명화] 고객사 Webview API 서비스 (Spring Boot + Kotlin)
> 재사용 목적: 동일 기술 스택(Spring Boot + Kotlin/Java)을 사용하는 타 레포/서비스에도 적용 가능

---


> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L20-36 (원문 보존, 익명화 적용)

### 1. 분석 방법론 개요

#### 핵심 원칙

Spring Boot 기반 서비스의 인증/인가 취약점은 크게 세 레이어에서 발생한다.

```
[클라이언트 UI]
    ↓  ← UI 레벨 강제 (우회 가능)
[컨트롤러 레이어]
    ↓  ← @Session / @Acl / 직접 검증 코드
[서비스 레이어]
    ↓  ← pinConfirmationDate 등 세션 필드 재검증
[DB / 외부 시스템]
```

**핵심 질문**: "이 API는 서버 레이어에서 진짜로 인증/인가를 검증하는가, 아니면 UI 레이어에만 의존하는가?"


> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L40-166 (원문 보존, 익명화 적용)

### 2. Step-by-Step 분석 절차

#### Step 1 — 커스텀 어노테이션/AOP 전수 조사

서비스마다 자체 구현한 인증/접근 제어 메커니즘이 있다. 먼저 이것을 파악한다.

**검색 방법**:
```bash
# 커스텀 어노테이션 찾기
grep -r "@interface" src/ --include="*.java" --include="*.kt"

# AOP Advice 찾기
grep -r "@Aspect\|@Before\|@Around\|@After" src/ --include="*.java" --include="*.kt"

# Spring Security 설정 찾기
grep -r "WebSecurityConfigurerAdapter\|SecurityFilterChain\|HttpSecurity" src/
```

**익명화 사례 분석에서 발견한 패턴**:
- `@Session(field, required)` — 세션 주입 어노테이션
- `@Acl(ip = "...")` — IP 화이트리스트 어노테이션
- `AclAdviser.java` — `@Acl` 처리 AOP

**확인해야 할 것**:
1. 어노테이션 구현 파일을 찾아서 실제 동작 방식 확인
2. AOP에서 파라미터를 어떻게 추출하는지 확인 (메서드 파라미터 의존 여부)
3. 환경별 분기 로직 확인 (`local`, `dev`, `prod` 등)

**전역 인증 강제 유형 분류**:

| 인증 강제 유형 | 위험 수준 | 특징 |
|--------------|---------|------|
| Spring Security `authorizeRequests()` 전역 설정 | 낮음 | Whitelist 기반, 누락 경로 = 거부 |
| AOP + 파라미터 어노테이션 방식 | **높음** | 어노테이션 누락 = 인증 없음 |
| Interceptor 방식 | 중간 | `excludePathPatterns` 확인 필요 |
| 전역 강제 없음 | **치명** | 모든 엔드포인트 개별 확인 필요 |

```bash
# Spring Security 존재 여부 확인
grep -rn "SecurityConfig\|WebSecurityConfigurerAdapter\|SecurityFilterChain\|@EnableWebSecurity" \
  --include="*.java" --include="*.kt" src/

# 전역 인터셉터 등록 확인
grep -rn "addInterceptors\|HandlerInterceptor\|InterceptorRegistry" \
  --include="*.java" --include="*.kt" src/
```

---

#### Step 2 — @Session 어노테이션 분석

##### 2-1. 어노테이션 선언 확인

`@Session` 어노테이션의 `required` 값을 전수 조사한다.

```bash
grep -rn "@Session" src/ --include="*.kt" --include="*.java" | grep "required = true\|required = false"
```

| `required` 값 | 의미 |
|---|---|
| `true` | 세션 없으면 요청 차단 |
| `false` | 세션 없어도 통과 (비로그인 허용) |
| 없음(기본값) | 구현 코드 확인 필요 |

##### 2-2. 결제/민감 API에서 required = false 또는 누락 패턴 탐지

```bash
# 결제, 취소, 배치, 관리 관련 엔드포인트 중 세션 검증이 없는 것
grep -rn "PostMapping\|PutMapping\|DeleteMapping" src/ --include="*.kt" | grep -i "pay\|purchase\|cancel\|batch\|admin\|settle"
```

결제·취소·배치 관련 API는 반드시 `required = true` 또는 직접 세션 검증이 있어야 한다.

##### 2-3. AOP Pointcut 범위 확인

AOP가 클래스 레벨 어노테이션 기반인지, 파라미터 레벨 어노테이션 기반인지에 따라 누락 가능성이 달라진다.

```bash
# Pointcut 표현식 확인
grep -rn "@Pointcut\|execution(" --include="*.java" --include="*.kt" src/
```

| 어노테이션 레벨 | 동작 방식 | 누락 위험 |
|--------------|---------|---------|
| 클래스 레벨 | 해당 클래스 전체 메서드에 적용 | 클래스 어노테이션 누락 시 전체 미적용 |
| 파라미터 레벨 | 해당 파라미터에 개별 선언 필요 | 파라미터 어노테이션 누락 시 해당 메서드만 미적용 |

##### 2-4. 테스트 세션 ID 우회 패턴

개발 편의를 위해 특수 prefix를 사용해 외부 인증 서버 호출을 생략하는 패턴이 있다.

```bash
grep -rn "TEST_ID\|startsWith.*ID\|mock.*session\|testSession" \
  --include="*.java" --include="*.kt" src/
```

**취약 패턴**:
```java
// 취약: 외부 인증 서버 호출 없이 mock UserInfo 생성
if (sessionId.startsWith("TEST_ID:")) {
    // "TEST_ID:mbrId" 또는 "TEST_ID:mbrId:mdn" 파싱
    // → 외부 세션 인증 서버 호출 없이 임의 사용자로 동작
}
```

**판단 기준**: 이 패턴이 `local`/`dev` 환경이 아닌 곳에서도 동작하면 공격자가 임의의 사용자로 API 호출 가능.

```bash
# 분기 조건 확인
grep -rn "TEST_ID" src/ --include="*.java" --include="*.kt" -A5 | grep "active\|profile\|env"
```

##### 2-5. 인증 서버 타임아웃 처리 확인

외부 인증 서버 호출 실패 시 기본값이 인증 **통과(Fail-Open)**인지, **차단(Fail-Closed)**인지 확인한다.

```bash
grep -rn "timeout\|fallback\|catch.*Session\|null.*UserInfo\|InvalidSession" \
  --include="*.java" --include="*.kt" src/
```

| 처리 방식 | 판정 | 비고 |
|---------|------|------|
| 타임아웃 → 인증 통과 (Fail-Open) | **취약** | 인증 서버 장애 시 모든 요청 인증됨 |
| 타임아웃 → 예외 throw (Fail-Closed) | 안전 | |
| 타임아웃 → null UserInfo로 진행 | **취약** | NullPointerException 또는 무인증 진행 |


> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L249-353 (원문 보존, 익명화 적용)

### Step 4 — 배치/관리 API 무인증 접근 점검

배치 API는 개발 편의상 인증을 생략하는 경우가 많다.

```bash
# 배치/관리 컨트롤러 찾기
find src/ -name "*Batch*Controller*" -o -name "*Admin*Controller*" -o -name "*Manage*Controller*"

# 각 컨트롤러에서 @Session, @Acl 없는 엔드포인트 찾기
grep -A10 "@PostMapping\|@GetMapping\|@PutMapping" <파일> | grep -v "@Session\|@Acl"
```

**판단 기준**:
- `@Session` 없음 + `@Acl` 없음 → 인증/접근 제어 없음 → 누구나 호출 가능
- `@Acl` 있음 + `HttpServletRequest` 파라미터 없음 → AOP 동작 불가 → 사실상 무인증

---

### Step 5 — PIN/비밀번호 인증 서버 검증 점검

결제/구매 API는 UI에서 PIN 입력을 강제하더라도 **서버에서 PIN 확인 시각을 재검증**해야 한다.

#### 5-1. 세션 객체에서 PIN 관련 필드 찾기

```bash
grep -rn "pinConfirmationDate\|passwordConfirmationDate\|pinStatus" src/ --include="*.java" --include="*.kt"
```

#### 5-2. 결제 API에서 PIN 검증 로직 있는 패턴 (정상)

```kotlin
// SamplePayController.kt — 정상 패턴
val pinTimeDifferenceSeconds = if (userInfo.pinConfirmationDate != null) {
    (Math.abs(System.currentTimeMillis() - userInfo.pinConfirmationDate) / 1000).toInt()
} else { -1 }

if (pinTimeDifferenceSeconds == -1 || pinTimeDifferenceSeconds > 10) {
    throw ServiceRuntimeException(PIN_CONFIRMATION_ERROR.code())
}
```

#### 5-3. PIN 검증 없는 결제 API 찾기

```bash
# 결제 관련 Controller에서 pinConfirmationDate 검증 없는 것
grep -L "pinConfirmationDate\|passwordConfirmationDate" src/**/controller/**/*Pay*Controller* src/**/controller/**/*Purchase*Controller*
```

**Request Body DTO도 확인**: 요청 파라미터에 비밀번호 필드 자체가 없다면 UI 레벨에서만 강제하는 것.

```bash
grep -rn "password\|pin\|secret" src/**/dto/**/*Request* --include="*.kt" --include="*.java"
```

---

### Step 6 — IDOR (수평적 권한 상승) 점검

```bash
# 경로 파라미터나 요청 파라미터로 다른 사용자 리소스에 접근하는 패턴
grep -rn "PathVariable\|@RequestParam" src/ --include="*.kt" | grep -i "mbrId\|userId\|seq\|histSeq"
```

**점검 방법**:
1. API가 `mbrId` 또는 리소스 식별자를 파라미터로 받는가?
2. 서비스 레이어에서 `userInfo.mbrId == request.mbrId` 소유권 확인을 하는가?
3. 확인 없이 파라미터로 받은 ID 그대로 조회하는가?

**IDOR 위험도 분류**:

| 작업 유형 | 위험도 | 이유 |
|----------|--------|------|
| 취소/삭제 작업 | **높음** | 타인 데이터 파괴 |
| 개인정보 포함 조회 | **높음** | 프라이버시 침해 |
| 수정/변경 작업 | **높음** | 데이터 위변조 |
| 개인정보 미포함 조회 | 중간 | 데이터 노출 |

**IDOR 확정 조건** (아래 항목이 모두 해당되면 취약):

```
1. 엔드포인트에 인증 강제 없음 (@Session/@LoginUser 등 누락)
   또는 요청 바디/파라미터에서 소유자 ID를 직접 받음

2. 서비스 레이어에서 요청 ID를 세션 ID와 비교하지 않고 Repository에 그대로 전달

3. DB 쿼리 WHERE 절이 요청 바디의 ID를 그대로 사용
   (WHERE user_id = :requestMbrId  ← 취약)
   (WHERE user_id = :sessionMbrId  ← 안전)

4. 공격자가 다른 사용자의 ID를 요청에 포함할 수 있음
```

---

### Step 7 — 하드코딩된 인증 정보 점검

```bash
grep -rn "password\|secret\|key\|token" src/ --include="*.kt" --include="*.java" | grep '= "[^"]*"' | grep -v "//\|test\|Test"
```

**익명화 사례 분석 발견**:
```kotlin
// GroupBuyPaymentService.kt
const val FIXED_PAYMENT_PASSWORD = "[REDACTED]"  // 실제 결제 비밀번호 하드코딩
```


> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L387-436 (원문 보존, 익명화 적용)

### Step 9 — 세션/토큰 전달 방식 아키텍처 분석

인증 정보의 생성 주체와 서버 도달 경로를 파악한다. 아키텍처 유형에 따라 공격 벡터가 달라진다.

```bash
# 세션/토큰 헤더 키 확인
grep -rn "getHeader\|x-.*session\|x-.*token\|Authorization" \
  --include="*.java" --include="*.kt" src/ | grep -v "test\|Test"

# 외부 인증 서버 호출 URL 확인
grep -rn "session/info\|auth/validate\|token/verify\|checkSession" \
  --include="*.java" --include="*.kt" --include="*.properties" --include="*.yml" src/

# UserInfo 주입 방식 확인
grep -rn "HandlerMethodArgumentResolver\|resolveArgument\|@AuthenticationPrincipal" \
  --include="*.java" --include="*.kt" src/
```

**아키텍처 유형별 특징 및 주요 위험**:

| 유형 | 설명 | 주요 위험 |
|------|------|----------|
| Stateless (JWT) | 서버가 토큰 로컬 파싱 | 알고리즘 혼동, 만료 토큰 미검증 |
| Stateful (세션ID → 외부 서버) | 매 요청마다 인증 서버 호출 | 타임아웃 Fail-Open, SSRF |
| 네이티브 앱 → 웹뷰 헤더 주입 | 앱이 세션ID를 HTTP 헤더에 삽입 | TLS 미적용 시 헤더 탈취/위변조 |
| 쿠키 기반 | 브라우저 자동 전송 | CSRF, Secure/HttpOnly 플래그 미설정 |
| URL 파라미터 포함 | 세션ID가 URL에 노출 | 서버 로그·Referer 헤더에 세션 노출 |

**네이티브 앱 + 웹뷰 구조 특화 확인 포인트**:

```
□ 앱이 HTTP 헤더로 세션을 주입하는 구조인가?
    → 헤더 키 이름 확인 (예: x-svc-session-id)
    → TLS 미적용 구간에서 헤더 탈취/위변조 가능성 확인

□ Gateway/Zuul 필터가 헤더를 가공하는가?
    → 가공 과정에서 세션 헤더 덮어쓰기 가능 여부 확인
    → 외부에서 직접 주입 가능한 내부 헤더 여부 확인

□ 세션 ID가 URL 파라미터로 전달되는가?
    → 서버 로그, Referer 헤더에 세션 ID 노출 가능성

□ 웹뷰가 독자적으로 인증 처리를 하는가?
    → 앱 세션과 웹뷰 세션이 별도 관리되면 동기화 이슈 가능성

□ 게이트웨이 레벨에서 내부 API 경로를 차단하는가?
    → 예: /internal/* 경로에 대한 403 처리 여부 확인
    grep -rn "internal\|sendError.*403\|FORBIDDEN" \
      --include="*.java" --include="*.kt" src/
```


## Part C — 익명화 사례 (발견 취약점 목록 + 상세)

> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L440-454 (원문 보존, 익명화 적용)

### 3. 발견된 취약점 목록 (익명화 사례)

| # | 취약점 | 위치 | 위험도 |
|---|--------|------|--------|
| A-01 | PIN 인증 우회 (서버 검증 누락) | `SampleGroupBuyController.kt` L92-107 | 높음 |
| A-02 | 결제 비밀번호 하드코딩 | `GroupBuyPaymentService.kt` L41 | 높음 |
| A-03 | Race Condition — 구매 제한 우회 | `GroupBuyJoinService.kt` L45, L81 | 높음 |
| A-04 | 배치 API 무인증 접근 | `SampleRecommendController.kt` L43 | 중간 |
| A-05 | `@Acl` AOP 동작 불가 (HttpServletRequest 누락) | `SampleGroupBuyBatchController.kt` L32 | 중간 |
| A-06 | `String.contains()` 부분 IP 우회 | `AclAdviser.java` checkIpAcl() | 중간 |
| A-07 | local/dev 환경 ACL 완전 우회 | `AclAdviser.java` | 낮음(환경 의존) |

---

### 4. 취약점별 상세 분석


> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L456-499 (원문 보존, 익명화 적용)

### A-01: PIN 인증 우회

**위치**: `SampleGroupBuyController.kt:92-107`

**원인**: 다른 결제 API(`SamplePayController`, `SampleChargeService`)는 서버에서 `pinConfirmationDate` 타임스탬프를 검증하지만, 공동구매 `/join` API는 이 검증을 생략함.

```kotlin
// 취약한 코드 — pin 검증 없음
if (userInfo?.mbrId == null) {
    throw ServiceRuntimeException(CommonErrorCode.INVALID_SESSION.code())
}
// pinConfirmationDate 검증 없음 ← 결함
val groupBuy = groupBuyJoinService.getValidGroupBuy(...)
```

```kotlin
// 정상 패턴 (SamplePayController.kt 참고)
val pinTimeDiff = if (userInfo.pinConfirmationDate != null) {
    (Math.abs(System.currentTimeMillis() - userInfo.pinConfirmationDate) / 1000).toInt()
} else -1
if (pinTimeDiff == -1 || pinTimeDiff > 10) throw ServiceRuntimeException(PIN_ERROR)
```

**Request Body DTO 확인**: `GroupBuyJoinRequest`에 비밀번호/PIN 파라미터 자체 없음 → UI 레벨에서만 강제.

**PoC**: 세션 토큰만 보유한 상태에서 PIN 입력 없이 `/join` API 직접 호출.

**대응방안**: 컨트롤러에서 `userInfo.pinConfirmationDate` 타임스탬프 검증 추가 (10초 이내).

---

### A-02: 결제 비밀번호 하드코딩

**위치**: `GroupBuyPaymentService.kt:41`

```kotlin
const val FIXED_PAYMENT_PASSWORD = "[REDACTED]"
```

UI에서 사용자가 입력한 비밀번호와 무관하게 항상 이 값을 사용. UI 입력 검증이 형식적임.

**대응방안**: 환경 변수 또는 Vault/KMS로 주입.

---


> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L523-541 (원문 보존, 익명화 적용)

### A-04: 배치 API 무인증 접근

**위치**: `SampleRecommendController.kt:43-47`

```kotlin
@PostMapping("/batch/update")
open fun updateRecommendBatch(): ResponseEntity<Unit> {
    sampleRecommendService.createRecommendInfo(true)  // Redis 캐시 재구성
    return ResponseEntity.ok().build()
}
```

`@Session`, `@Acl` 모두 없음 → 인터넷에서 접근 가능한 경우 누구나 호출 가능.

**영향**: 추천 콘텐츠 강제 재계산, Redis 캐시 무단 초기화 → 서비스 성능 저하.

**대응방안**: `@Acl(ip = "내부 배치 서버 IP")` 추가 또는 내부망 전용 포트/경로 분리.

---


## Part D — 체크리스트 / 최종 판단 요약 / 검색 명령 부록

> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L598-610 (원문 보존, 익명화 적용)

### 5. 체크리스트

#### 인증 체크리스트

- [ ] 결제/구매 API에 `@Session(required = true)` 또는 동등한 세션 검증이 있는가?
- [ ] PIN 입력이 필요한 API에서 서버 측 `pinConfirmationDate` 타임스탬프 검증을 수행하는가?
- [ ] Request Body DTO에 PIN/비밀번호 파라미터가 있는가? (없으면 UI 레벨에서만 강제)
- [ ] 배치/관리 API에 `@Session`, `@Acl` 등 접근 제어가 있는가?
- [ ] 인증 정보(비밀번호, 키)가 소스코드에 하드코딩되어 있지 않은가?
- [ ] 인증 방식이 AOP + 어노테이션 방식인가? (전역 강제 여부 확인)
- [ ] AOP Pointcut이 파라미터 레벨 어노테이션 기반인가? (누락 시 미적용 가능성)
- [ ] 테스트 세션 ID 우회 패턴(`TEST_ID:` 등)이 개발 환경 외에서도 동작하는가?
- [ ] 외부 인증 서버 타임아웃 시 기본값이 인증 통과(Fail-Open)인가?


> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L627-639 (원문 보존, 익명화 적용)

### IDOR 체크리스트

- [ ] 경로 파라미터/요청 파라미터로 받은 리소스 ID에 대해 소유권 확인을 하는가?
- [ ] `mbrId` 또는 `userId`를 파라미터로 받을 경우, 세션의 `userInfo.mbrId`와 일치 여부를 확인하는가?
- [ ] 취소/삭제 작업에서 요청 바디의 소유자 ID를 세션과 비교하는 로직이 있는가?
- [ ] DB 쿼리 WHERE 절의 `user_id`가 세션에서 온 값인가, 요청 바디에서 온 값인가?

### 세션/토큰 전달 방식 체크리스트

- [ ] 세션 ID가 HTTP 헤더로 전달되는가? (헤더 탈취 경로 확인)
- [ ] 세션 ID가 URL 파라미터에 포함되는가? (로그·Referer 노출 위험)
- [ ] 네이티브 앱 + 웹뷰 구조인 경우 앱이 헤더를 주입하는 방식인가?
- [ ] Gateway/Zuul 필터에서 내부 API 경로(`/internal/*`)를 외부에서 차단하는가?


> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L641-712 (원문 보존, 익명화 적용)

---

### 6. 취약점 최종 판단 요약

| 패턴 | 판정 | 비고 |
|------|------|------|
| Spring Security 전역 인증 설정 있음 | 설정 내용에 따름 | `permitAll()` 범위 별도 확인 |
| AOP 인증 방식, 엔드포인트에 어노테이션 누락 | **취약** | 인증 검사 미적용 |
| `@Session(required = false)` | 비로그인 허용 | 비즈니스 요구사항 확인 필요 |
| AOP Pointcut이 파라미터 레벨, 파라미터 어노테이션 누락 | **취약** | 해당 메서드 인증 미적용 |
| 테스트 세션 ID 우회(`TEST_ID:` 등), 비개발 환경에서 동작 | **높음** | 임의 사용자 사칭 가능 |
| 인증 서버 타임아웃 → 인증 통과 (Fail-Open) | **높음** | 인증 서버 장애 시 전체 무인증 |
| 요청 바디 `mbrId` → DB 조회, 세션 비교 없음 | **IDOR** | 소유권 검증 누락 |
| IDOR + 취소/삭제 작업 | **높음** | 타인 데이터 파괴 가능 |
| IDOR + 개인정보 포함 조회 | **높음** | 프라이버시 침해 |
| Admin 엔드포인트, `@Acl`·`@Session` 모두 없음 | **치명** | 무인증 관리 기능 노출 |
| `@Acl` 있으나 `HttpServletRequest` 파라미터 없음 | **취약** (ACL 미동작) | AOP IP 추출 불가 |
| ACL 환경 우회(dev/local), dev 서버 외부 노출 | **높음** | 실질적 ACL 없음 |
| ACL IP 비교에 `contains()` 사용 | **ACL 우회** | `equals()`/`Set.contains()` 사용 필요 |
| 로드밸런서 환경, `getRemoteAddr()` 단독 사용 | **높음** | 항상 프록시 IP 반환, IP ACL 무력화 |
| `X-Forwarded-For` 검증 없이 신뢰 | **높음** | 헤더 위조로 IP 우회 가능 |
| PIN 검증을 UI에서만 강제, 서버 미검증 | **높음** | API 직접 호출로 PIN 우회 |
| 결제 비밀번호 소스코드 하드코딩 | **높음** | 코드 노출 시 인증 형식화 |
| Race Condition, 검증·저장 트랜잭션 분리 | **높음** | 횟수 제한 우회 가능 |
| 세션 ID가 URL 파라미터에 포함 | 중간 | 로그·Referer 노출 |
| `X-Forwarded-For` 신뢰하지 않음, 프록시 환경 | 중간 | 실제 클라이언트 IP 식별 불가 |

---

### 부록 — 유용한 검색 명령어

```bash
# 커스텀 어노테이션 전수 조회
grep -rn "@Session\|@Acl\|@Auth" src/ --include="*.kt" --include="*.java"

# 결제 관련 API 목록
grep -rn "PostMapping\|PutMapping" src/ --include="*.kt" | grep -i "pay\|purchase\|join\|buy"

# pinConfirmationDate 검증 위치
grep -rn "pinConfirmationDate\|passwordConfirmationDate" src/ --include="*.kt" --include="*.java"

# @Transactional 없는 서비스 메서드 (Race Condition 후보)
grep -rn "fun.*Purchase\|fun.*Join\|fun.*Buy" src/ --include="*.kt" | grep -v "@Transactional"

# 하드코딩된 자격증명
grep -rn 'val.*PASSWORD\|val.*SECRET\|val.*TOKEN\s*=\s*"' src/ --include="*.kt"

# FOR UPDATE 사용 여부
grep -rn "FOR UPDATE\|forUpdate\|PESSIMISTIC" src/ --include="*.kt" --include="*.java" --include="*.xml"

# 전역 인증 강제 방식 확인
grep -rn "SecurityFilterChain\|WebSecurityConfigurerAdapter\|addInterceptors\|@Aspect" \
  src/ --include="*.java" --include="*.kt"

# AOP Pointcut 범위 확인
grep -rn "@Pointcut\|execution(" src/ --include="*.java" --include="*.kt"

# 테스트 세션 ID 우회 패턴
grep -rn "TEST_ID\|startsWith.*ID\|mock.*session" src/ --include="*.java" --include="*.kt"

# 인증 서버 타임아웃/에러 처리
grep -rn "timeout\|fallback\|catch.*Session\|InvalidSession" src/ --include="*.java" --include="*.kt"

# X-Forwarded-For 처리 방식
grep -rn "X-Forwarded-For\|getRemoteAddr\|x-forwarded-for" src/ --include="*.java" --include="*.kt"

# 세션/토큰 헤더 전달 방식
grep -rn "getHeader.*session\|getHeader.*token\|addHeader.*session" src/ --include="*.java" --include="*.kt"

# Gateway 내부 경로 차단 여부
grep -rn "internal\|sendError.*403\|FORBIDDEN" src/ --include="*.java" --include="*.kt"
```
