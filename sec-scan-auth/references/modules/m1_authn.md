## Module M1 — authn (인증 강제 · 세션 · Fail-Open · 세션/토큰 전달구조)

**실행 조건**: `auth_map.module_plan.M1.run == true`
**Auto-Scan 연결**: `scan_missing_session_annotation`(`--skip session`), `scan_test_session_bypass`(`--skip testbypass`)
**finding category**: `AUTH_BYPASS`, `SESSION_TOKEN_EXPOSURE`, (A-6 내부경로) `INTERNAL_API_EXPOSURE`
**ID 접두어(task26_llm.json)**: `AUTH-BYP-NNN`, `AUTH-SESS-NNN`, `AUTH-IAE-NNN`

> 근거 원본 (원문 보존본): `methodology/auth_methodology.md`
> - Part A 5-1 / 5-2 / 5-6 (PHASE 5 구조화 절차)
> - Part B Step 1 (커스텀 어노테이션/AOP, 전역 인증 강제 유형), Step 2 (@Session), Step 7 (하드코딩 인증정보 — 경계 규칙 참조), Step 9 (세션/토큰 전달 아키텍처)
> - Part D 인증 체크리스트 / 세션·토큰 전달 방식 체크리스트 / 최종 판단 요약
> 판정이 애매하면 위 원문 절을 직접 읽고 판단한다.

> **경계 (기존 유지)**: JWT 알고리즘/서명 결함, CORS 설정, DTO 필드 과다노출은 `sec-scan-data`(Task 2-5) 소관이다.
> **경계 (추가)**: 하드코딩된 비밀번호/키/토큰 자체는 `sec-scan-data`의 `HARDCODED_SECRET` 소관이다 (원본 Auth_Analysis Scope: "Hardcoded credentials → DataProtection_Analysis.md").
> 이 모듈에서는 finding을 만들지 않고 `manual_review_note`에 "sec-scan-data 영역" 메모만 남긴다.
> 단, **사용자가 입력한 결제 비밀번호/PIN을 무시하고 하드코딩 값으로 대체**하는 구조(원본 사례 A-02)는 인증 형식화 문제이므로 M3에서 `PIN_REVERIFICATION_MISSING`으로 판정한다.

---

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

**[추가] 판정 보강 (원본 Step 1 / 5-1)**:
- 커스텀 인증 어노테이션(`@Session`, `@LoginUser`, `@Auth` 등)마다 처리 AOP/Resolver 파일을 Read로 열어 **실제 차단 로직**(세션 없을 때 throw 하는지)을 확인한다. 어노테이션 선언만 있고 처리기가 없거나 처리기가 차단하지 않으면 → A-2 판정 기준으로 `AUTH_BYPASS` 검토.
- AOP에서 파라미터를 어떻게 추출하는지(메서드 파라미터 의존 여부)와 환경별 분기(`local`/`dev`/`prod`)를 함께 기록한다.
- Interceptor 방식이면 `excludePathPatterns(...)`를 반드시 확인한다. 결제/취소/정산/관리 경로가 제외 목록에 포함되면 → **AUTH_BYPASS, 취약** (심각도는 A-2 기준).
  ```bash
  grep -rn "excludePathPatterns\|addPathPatterns" src/ --include="*.java" --include="*.kt" -A 5
  ```
- 결과를 `auth_access_assessment.global_auth_enforcement`에 기록 (`spring_security | aop_annotation | interceptor | none`).
- 올바른 패턴 참고 (원본 5-1): `requestMatchers(whitelist).permitAll().anyRequest().authenticated()`

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

**[추가] 판정 보강 (원본 Step 2-1 / 5-2)**:
- `required` 속성이 없는 `@Session` 사용처는 어노테이션 정의 파일에서 **기본값**을 확인한 뒤 위 기준을 적용한다 (원본 표: `true`=세션 없으면 차단 / `false`=비로그인 허용 / 없음=구현 코드 확인 필요).
- `required = false`가 결제·취소·민감 API가 아닌 곳에 있으면 finding을 만들지 않고 "비로그인 허용 — 비즈니스 요구사항 확인" 수준으로 `evidence_trail[]`에 기록한다 (원본 최종 판단 요약: "비로그인 허용 | 비즈니스 요구사항 확인 필요").
- 인증 서버 타임아웃 처리 판정표 (원본 Step 2-5): 타임아웃 → 인증 통과(Fail-Open) **취약** / 예외 throw(Fail-Closed) 안전 / null UserInfo로 진행 **취약**.
- JWT 시크릿 전 환경 동일 여부 자체의 판정은 `sec-scan-data` 소관이다. 이 모듈에서는 Fail-Open finding의 `manual_review_note`에 연계 위험으로만 적는다.
- **verification_status**: 테스트 세션 우회 비게이팅·`required=false`·어노테이션 누락은 코드로 확정 가능 → `code-confirmed`. 타임아웃 Fail-Open은 분기 코드가 명확하면 `code-confirmed`, 외부 라이브러리/설정(타임아웃 값, fallback 빈)에 의존하면 `needs-dynamic-verification`.

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

**[추가] 아키텍처 유형 분류 — summary_auth.md 「인증 아키텍처 요약」에 기록 (원본 Step 9 / 5-6)**:

| 유형 | 설명 | 주요 위험 | 이 skill에서의 처리 |
|------|------|----------|------|
| Stateless (JWT) | 서버가 토큰 로컬 파싱 | 알고리즘 혼동, 만료 토큰 미검증 | 판정은 sec-scan-data (`JWT_INCOMPLETE`), 여기서는 유형만 기록 |
| Stateful (세션ID → 외부 서버) | 매 요청마다 인증 서버 호출 | 타임아웃 Fail-Open, SSRF | Fail-Open → A-2 / SSRF → 아래 보강 |
| Native App → Webview 헤더 주입 | 앱이 세션ID를 HTTP 헤더에 삽입 | TLS 미적용 시 헤더 탈취/위변조 | 위 판정 + M5 실행 |
| 쿠키 기반 | 브라우저 자동 전송 | CSRF, Secure/HttpOnly 플래그 미설정 | CSRF → M2 B-1 / 플래그 → 아래 보강 |
| URL 파라미터 포함 | 세션ID가 URL에 노출 | 서버 로그·Referer 헤더에 세션 노출 | 위 판정 |

**[추가] 판정 보강**:
- **헤더 키 이름 기록**: 세션/토큰 헤더 키 이름을 찾아 summary 아키텍처 요약에 기록한다 (`code_snippet`에는 헤더 **값** 원문 금지 — RULE-3).
- **Stateful 외부 인증 서버 호출의 SSRF 위험**: 인증 서버 호출 URL/호스트가 요청 값(헤더·파라미터)으로 조립되는지 확인한다. 설정값 고정 URL이면 양호. 요청 값이 URL/호스트에 들어가면 → **AUTH_BYPASS, 정보**로 기록하고 `manual_review_note`에 "SSRF 가능성 — 요청 값이 인증 서버 호출 URL에 반영됨"을 적는다 (taxonomy에 SSRF category가 없으므로 정보 등급, 판정은 사람 검토).
  ```bash
  grep -rn "restTemplate\|WebClient\|feignClient" src/ --include="*.java" --include="*.kt" -A 5 | grep -i "session\|auth\|token" | grep -i "getHeader\|getParameter\|request\."
  ```
- **쿠키 플래그**: 서버가 세션 쿠키를 직접 발급하는 경우 `Secure`/`HttpOnly`/`SameSite` 설정을 확인한다. 미설정 → **SESSION_TOKEN_EXPOSURE, 취약, Medium**. 쿠키를 인프라(LB/Gateway)에서 붙이는 구조라 코드에서 확인 불가하면 `needs-dynamic-verification`.
  ```bash
  grep -rn "ResponseCookie\|new Cookie(\|setHttpOnly\|setSecure\|SameSite\|server\.servlet\.session\.cookie" src/ . --include="*.java" --include="*.kt" --include="*.yml" --include="*.properties" -n
  ```
- **Gateway/Zuul 헤더 가공과 덮어쓰기**: Gateway/Filter가 인증 결과를 내부 헤더(예: 사용자 ID 헤더)로 붙여 하위 서비스에 전달하는 구조라면, **클라이언트가 보낸 같은 이름의 헤더를 먼저 제거하는지** 확인한다. 제거하지 않고 하위 서비스가 그 헤더를 신뢰하면 → **AUTH_BYPASS, 취약, Critical** (외부에서 내부 헤더 주입으로 사용자 위장). Gateway 코드가 이 repo에 없으면 하위 서비스의 신뢰 지점을 기록하고 `needs-dynamic-verification`.
  ```bash
  grep -rn "addZuulRequestHeader\|mutate()\.header\|request\.mutate\|removeRequestHeader\|setRequestHeader\|ZuulFilter\|GlobalFilter" src/ --include="*.java" --include="*.kt" -B 2 -A 5
  ```
- **내부 경로 차단 방식**: `/internal`, `/admin` 차단이 URI prefix 문자열 비교(`startsWith`)만으로 되어 있으면 경로 정규화 차이(대소문자, 중복 슬래시, 인코딩, matrix parameter)로 우회될 수 있다 → **INTERNAL_API_EXPOSURE, 취약, High** 후보, 정규화 처리 여부를 코드로 확인 못 하면 `needs-dynamic-verification` (원본 Webview 5.6 "URI prefix 매칭만 사용 시 우회 가능성").
- **Native App + Webview 구조가 확인되면** `auth_map.module_plan.M5.run = true`로 갱신하고 M5를 실행한다 (원본 5-6: WEBVIEW_SESSION_ANALYSIS 추가 실행 지시).
- 웹뷰가 독자적으로 인증 처리를 해 앱 세션과 웹뷰 세션이 별도 관리되면 동기화 이슈 가능성을 M5 5.3에서 확인한다.

---

### M1 판정 요약표 (summary_auth.md 「모듈별 판정 요약」에 채움 — 원본 Final Verdict Summary Table 매핑)

각 행에 `양호` / `취약(finding_id)` / `이상 없음` / `해당없음` 중 하나를 기록한다. 원본 지시("취약점이 없으면 '이상 없음' 기록")를 이 표로 대체한다.

| 점검 항목 | 양호 기준 | 취약 기준 |
|---|---|---|
| 인증 강제 유형 | Spring Security 전역 설정 (Whitelist 기반) | AOP 어노테이션 방식에서 어노테이션 누락; 또는 전역 강제 없음 |
| AOP Pointcut 범위 | 클래스 레벨 어노테이션으로 전체 적용 | 파라미터 레벨에서 어노테이션 누락 시 해당 메서드 인증 미적용 |
| Interceptor 제외 경로 | 민감 경로가 `excludePathPatterns`에 없음 | 결제/취소/관리 경로가 제외 목록에 포함 |
| @Session required=false | 비로그인이 허용되는 공개 API에만 적용 | 결제·취소·민감 API에 required=false 또는 @Session 누락 |
| 테스트 세션 우회 (TEST_ID 등) | local/dev 환경에서만 동작, 운영 환경에서 비활성화 | 비개발 환경에서도 동작 → 임의 사용자 사칭 가능 |
| 인증 서버 Fail-Open | 타임아웃 → 예외 throw (Fail-Closed) | 타임아웃 → 인증 통과 또는 null UserInfo로 진행; 서비스 레이어 내 환경별 강제 성공 처리 |
| `anyRequest().permitAll()` 단일 방어선 | `requestMatchers(whitelist).permitAll().anyRequest().authenticated()` 구성 | `anyRequest().permitAll()` → Spring Security 인가 레이어 무효화; 커스텀 필터 단독 의존 구조 |
| 세션 URL 노출 | 세션ID/토큰이 HTTP 헤더 또는 쿠키로만 전달 | 세션ID가 URL 파라미터에 포함 → 서버 로그·Referer 노출 |
| Webview 헤더 주입 | TLS 적용, Gateway에서 내부 헤더 외부 주입 차단 | TLS 미적용 구간 존재; 또는 외부에서 내부 헤더 덮어쓰기 가능 |
| 쿠키 플래그 | Secure/HttpOnly/SameSite 설정 | 미설정 |
| 외부 인증 서버 호출 URL | 설정값 고정 | 요청 값이 URL/호스트에 반영 (SSRF 가능성) |
| 내부 경로 차단 | Gateway에서 `/internal/*` 403 + 경로 정규화 후 비교 | 차단 없음 또는 prefix 문자열 비교만 사용 |
