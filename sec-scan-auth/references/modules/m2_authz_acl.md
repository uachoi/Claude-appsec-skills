## Module M2 — authz-acl (IDOR · 배치/관리자 권한 · Spring Security ACL · 커스텀 @Acl · IP ACL 우회)

**실행 조건**: `auth_map.module_plan.M2.run == true`
**Auto-Scan 연결**: `scan_idor_candidates`(`--skip idor`), `scan_permitall_antmatchers`(`--skip permitall`), `scan_ip_acl_bypass`(`--skip ipacl`), `scan_missing_acl_admin_batch`(`--skip aclcoverage`)
**finding category**: `IDOR`, `PRIVILEGE_ESCALATION`, `BROKEN_ACCESS_CONTROL`, `IP_ACL_BYPASS`, `INTERNAL_API_EXPOSURE`
**ID 접두어(task26_llm.json)**: `AUTH-IDOR-NNN`, `AUTH-PRIV-NNN`, `AUTH-BAC-NNN`, `AUTH-IPACL-NNN`, `AUTH-IAE-NNN`

> 근거 원본 (원문 보존본):
> - `methodology/auth_methodology.md` Part A 5-3 / 5-5, Part B Step 4 / Step 6, Part D IDOR 체크리스트
> - `methodology/acl_methodology.md` Part A 4-1 ~ 4-4, Part B (@Acl AOP 구현 분석), Part C 익명화 사례 A-05 ~ A-07, Part D 접근 제어 체크리스트
> - `methodology/auth_methodology.md` Part C 익명화 사례 A-04 (배치 API 무인증)
> 판정이 애매하면 위 원문 절을 직접 읽고 판단한다.

> **ip_acl == false** 이면 B-2 / B-3은 "해당없음(커스텀 IP ACL 없음)"으로 기록하고 건너뛴다. `spring_security_rules == false`이면 B-1은 "해당없음(Spring Security 인가 규칙 없음)".

---

### A-3. 배치/관리자 API 인증 커버리지 (Auth 5-3)

```bash
find src/ -name "*Batch*Controller*" -o -name "*Admin*Controller*" -o -name "*Internal*Controller*" -o -name "*Manage*Controller*" 2>/dev/null
grep -rn "@PostMapping\|@GetMapping\|@PutMapping\|@DeleteMapping\|@RequestMapping" src/ --include="*.java" --include="*.kt" -B 10 | grep -B 9 "batch\|admin\|internal\|system\|settle\|cron" | grep -v "@Session\|@PreAuthorize\|@Secured"
grep -rn "@RestController\|@Controller" src/ --include="*.java" --include="*.kt" -l | xargs grep -L "@Session\|@PreAuthorize\|@Secured\|@LoginUser" 2>/dev/null
```

**판정**: `@Session`과 `@Acl` 모두 누락 → **PRIVILEGE_ESCALATION, 취약, Critical** (무인증 접근 가능). `@Session` 없고 `@Acl`만 있음 → B-3(IP ACL) 절차로 우회가능성 확인 후 판정.

**[추가] 심각도 조정 (원본 사례 A-04와 기본값 충돌 정리)**:
- 기본값은 Critical을 유지한다 (taxonomy·severity_criteria: "금전/회원상태 직접 변경 가능 → 5등급 유력").
- 해당 엔드포인트의 **실제 영향**을 코드로 확인해 하향할 수 있다. 원본 사례 A-04(추천 캐시 재구성 배치, 무인증)는 영향이 "추천 콘텐츠 강제 재계산, Redis 캐시 무단 초기화 → 서비스 성능 저하"라 **중간**으로 평가되었다.
  | 영향 | severity |
  |---|---|
  | 금전·포인트·정산·회원상태·권한 변경, 개인정보 대량 조회 | Critical |
  | 데이터 변경(위 외), 외부 발송(문자/메일/푸시) | High |
  | 캐시 재구성·재계산 등 가용성/성능 영향만 | Medium |
- 하향 시 `manual_review_note`에 `severity 조정: Critical → Medium (사유: 캐시 재구성만 수행, 데이터 변경 없음)` 형식으로 근거를 남긴다.
- 컨트롤러별 표(원본 5-3)는 B-4 표와 합쳐 RULE-4 `review_note` 섹션으로 작성한다.

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

**[추가] 판정 보강 (원본 Step 6 / 5-5)**:
- 원본 위험도 표의 **수정/변경 작업 → 높음 (데이터 위변조)** 을 명시 적용한다 (개인정보 포함 여부와 무관).
- 조건 1은 원본 Step 6 표현대로 "엔드포인트에 인증 강제 없음(@Session/@LoginUser 등 누락) **또는** 요청 바디/파라미터에서 소유자 ID를 직접 받음"까지 포함한다.
- 비교 기준: `WHERE user_id = :requestMbrId` → 취약 / `WHERE user_id = :sessionMbrId` → 안전. MyBatis XML(`#{mbrId}`)이면 매퍼 호출부에서 그 값이 요청에서 왔는지 세션에서 왔는지 역추적한다.
- 조건 4(치환 가능성)는 ID가 순차/예측 가능한지, 다른 사용자 ID를 얻을 경로가 있는지를 코드로 판단한다. UUID 등 추측 불가 ID라도 조건 1~3이 충족되면 취약으로 두되 `manual_review_note`에 ID 형식을 기록한다.
- **verification_status**: 조건 1~3을 코드로 모두 확인하면 `code-confirmed`. 서비스 레이어가 외부 API에 위임해 소유권 검증 여부를 이 repo에서 확인할 수 없으면 `needs-dynamic-verification` + `result: "정보"`.

**[v2 추가] 소유권 검증 상태 3분류** — 정적 분석은 "검증 코드가 있는가"까지만 확정할 수 있다. 검증 코드가 있어도 실제로 모든 경로에서 동작하는지는 코드만으로 보장되지 않으므로, 상태를 나눠 기록한다.

| 상태 | 코드 상태 | 처리 |
|---|---|---|
| 검증 없음 | 조건 1~3 충족 | 위 판정대로 `IDOR, 취약`, `code-confirmed` |
| 간접 검증 | 소유권 확인이 공통 Resolver·AOP·외부 API·DB 뷰/정책 등 이 메서드 밖에서 이뤄져, 대상 엔드포인트에 적용되는지 경로 전체를 확인하지 못함 | `IDOR, 정보`, `needs-dynamic-verification` → DAST 후보 (`kind: "idor"`) |
| 직접 검증 | 서비스 레이어에서 `requestId == sessionId` 비교 또는 `WHERE`에 세션 ID 사용을 Read로 확인 | 양호 — `evidence_trail[]`에 검증 위치 기록 |

- DAST 후보의 `code_signals`에는 객체 참조 파라미터 이름(예: `orderId`)과 위치(path/query/body), 검증 위치(파일:라인 또는 "확인 못 함"), 리소스 작업 유형(조회/수정/삭제)만 적는다.
- `auth_map.endpoints[]`의 `tags`에 `resource_id`가 있는 엔드포인트를 대상 목록으로 쓴다.

---

### B-1. Spring Security ACL 분석 (ACL 4-1)

```bash
find src -name "*SecurityConfig*" -o -name "*SecurityConfiguration*" -o -name "*WebSecurityConfig*" 2>/dev/null
grep -rn "antMatchers\|requestMatchers\|authorizeRequests\|authorizeHttpRequests" src/ --include="*.java" --include="*.kt" -A 5
grep -rn "hasIpAddress" src/ --include="*.java" --include="*.kt" -A 3
grep -rn "permitAll\(\)" src/ --include="*.java" --include="*.kt" -B 2 -A 1
grep -rn "csrf\(\)\|csrf\.disable\|CsrfConfigurer" src/ --include="*.java" --include="*.kt" -A 3
```

**판정**: 불필요하게 넓은 `permitAll()` 범위 → **BROKEN_ACCESS_CONTROL, 취약, High**. 근거 없는 `csrf().disable()`(stateless JWT REST API 등 문서화된 근거 없음) → **BROKEN_ACCESS_CONTROL, 취약, Medium**.

**[추가] 판정 보강 (원본 4-1)**:
- `hasIpAddress()` 규칙이 admin/internal 엔드포인트에만 정확히 걸려 있는지 확인한다. 범위가 넓거나 엉뚱한 경로에 걸려 있으면 → **BROKEN_ACCESS_CONTROL, 취약, Medium** (프록시 환경이면 B-3 Vuln 3 기준도 함께 적용).
- CSRF 비활성화의 "근거" 판단: 세션 쿠키를 인증에 쓰는 구조(M1 A-6 아키텍처 = 쿠키 기반)면 근거 불인정, 헤더 토큰 전용 stateless API면 근거 인정(양호).

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

**[추가] 판정 보강 (원본 4-2 / Step 3-1 / 사례 A-05·A-07)**:
- `@Acl` 정의 파일에서 확인:
  - `@Target` — 메서드/클래스 중 어디에 붙일 수 있는지. 클래스에 붙였는데 `@Target(METHOD)`뿐이면 적용 안 됨.
  - `@Retention` — **`RUNTIME`이어야 AOP가 동작**. `CLASS`/`SOURCE`(Kotlin `BINARY`/`SOURCE`)이면 모든 `@Acl`이 무효 → **INTERNAL_API_EXPOSURE, 취약, High** (전역 영향, `affected_endpoints`에 `"path": "전역 (전체 API)"`).
  - 속성 목록: `ip`, `host`, `regEx` 등 → B-4 분류에 사용.
- AOP의 request 추출 방식 (원본 Step 3-1 취약 패턴 1):
  - `joinPoint.getArgs()`에서 `HttpServletRequest`를 찾고 없으면 `RequestNotFoundException`을 던지는 구조인지 확인한다.
  - 그 예외가 **throw되어 요청이 차단되는지, 상위에서 catch/무시되어 IP 검증 없이 진행되는지**를 끝까지 추적한다 (원본 Step 3-2: "AOP가 `RequestNotFoundException`을 throw하는가, catch하는가? 예외 발생 시 차단되는가, 허용되는가?").
  - catch/무시 → 해당 `@Acl` 메서드는 무ACL → **INTERNAL_API_EXPOSURE, 취약, High**. throw되어 차단 → 정상 호출도 실패하는 기능 결함이므로 보안 finding이 아니며 `evidence_trail`에 "ACL 차단 동작, 기능 오류 가능" 기록.
  - 개선 방향: 메서드 시그니처에 `request: HttpServletRequest` 추가, 또는 AOP에서 `RequestContextHolder`로 request 직접 획득.
- 환경 우회(원본 사례 A-07 "낮음(환경 의존)")의 심각도: dev/stage 서버가 외부에 노출된다는 근거(설정의 외부 도메인, 공개 DNS 이름 등)가 코드/설정에 있으면 High, 근거가 없으면 Medium(기존 task_26 판정 기준표 "외부 비접근 서버"), 외부 노출 여부를 알 수 없으면 Medium + `needs-dynamic-verification`.

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

**[추가] 판정 보강 (원본 4-3 / Step 3-3 / 사례 A-06)**:
- Vuln 2의 `realIP`가 `getRemoteAddr()`(TCP 레벨)에서 오면 직접 조작은 어렵지만, 프록시/LB 환경에서는 모든 트래픽이 프록시 IP로 들어오므로 그것만으로 충분한 통제가 아니다 (원본 4-3 Vuln 2 Note). 이 경우 Vuln 3 판정과 함께 기록한다.
- Vuln 3의 환경 판단 (원본 Step 3-3 표):
  | IP 추출 방식 | 환경 | 위험 |
  |---|---|---|
  | `getRemoteAddr()` 단독 사용 | 직접 연결 | 허용 (TCP 레벨 IP) |
  | `getRemoteAddr()` 단독 사용 | 프록시/LB 환경 | 항상 프록시 IP 반환 → IP ACL 무력화 |
  | `X-Forwarded-For` 신뢰 | 모든 환경 | 헤더 위조로 허용 IP 사칭 가능 |
  | `X-Forwarded-For` + 신뢰 프록시 목록 검증 | 권장 | 안전 |
- `RemoteIpFilter`(Tomcat) / `ForwardedHeaderFilter`(Spring) / `server.forward-headers-strategy` 설정이 있으면 **신뢰 프록시 IP 범위를 제한하는지**(`internalProxies`, `trustedProxies` 등) 확인한다. 제한 없이 활성화 → XFF 무조건 신뢰와 동일하게 판정.
- 프록시/LB 존재 여부는 대개 이 repo만으로 확정할 수 없다. 설정(`forward-headers-strategy`, 배포 매니페스트, Gateway 존재)으로 판단이 안 되면 `needs-dynamic-verification`으로 표시하고, 원본 최종 판단 요약의 "`X-Forwarded-For` 신뢰하지 않음, 프록시 환경 → 중간 (실제 클라이언트 IP 식별 불가)" 기준을 적용해 **Medium**으로 둔다.
- 사례 A-05 / A-06의 원본 위험도는 "중간"이다. 대상이 내부 배치(정산 등 금전 영향)이면 High 유지, 영향이 제한적이면 Medium으로 조정하고 사유를 `manual_review_note`에 남긴다.

### B-4. 전체 ACL 커버리지 감사 (ACL 4-4)

```bash
grep -rn "@Acl(" src/ --include="*.java" --include="*.kt" -A 2
grep -rn "@RestController\|@Controller" src/ --include="*.java" --include="*.kt" -l | xargs grep -L "@Acl\|@PreAuthorize\|@Secured" 2>/dev/null
grep -rn "@PostMapping\|@GetMapping\|@RequestMapping" src/ --include="*.java" --include="*.kt" -B 5 | grep -B 4 "batch\|admin\|internal\|system\|settle\|cron" | grep -v "@Acl\|@PreAuthorize"
grep -rn "@Session\|@Acl" src/ --include="*.java" --include="*.kt" -n | awk -F: '{print $1}' | sort | uniq -c | sort -rn
```

내부/배치/관리자 API 중 `@Acl`과 `@Session`/`@PreAuthorize` 모두 없음 → **INTERNAL_API_EXPOSURE, 취약, High**. `@Acl`은 있으나 `HttpServletRequest` 파라미터 누락(AOP가 인터셉트 불가) → **INTERNAL_API_EXPOSURE, 취약, High**. 이 항목은 표 전체를 `review_note`에 `## 무인증/무ACL 배치·관리자 엔드포인트 목록` 섹션으로 작성(RULE-4).

**[추가] 판정 보강 (원본 4-4)**:
- `@Acl` 사용처를 속성별로 분류한다:
  - `ip` → B-3 Vuln 2 / Vuln 3 확인
  - `host` → B-3 Vuln 1 확인
  - `regEx` → 정규식 비교가 **전체 문자열 일치**인지 확인. `Pattern.matches()`/`Matcher.matches()`/Kotlin `Regex.matches()`는 전체 일치(양호), `Matcher.find()`/`containsMatchIn()`은 부분 일치 → **IP_ACL_BYPASS, 취약, High**. 정규식에 `^...$` 앵커가 없는데 `find()`를 쓰는 경우도 부분 일치로 본다. 점(`.`) 미이스케이프 등 정규식 자체 결함도 기록한다.
  ```bash
  grep -rn "Pattern\.compile\|\.matcher(\|\.find()\|\.matches(\|Regex(\|containsMatchIn" src/ --include="*.java" --include="*.kt" -B 3 -A 3 | grep -i -B 3 -A 3 "acl\|ip\|host\|regex"
  ```
- 이중 보호 확인: 민감 API는 세션 인증 **과** IP ACL을 함께 갖는 것이 권장된다. 한쪽만 있으면 표에 "확인 필요"로 기록한다.
- RULE-4 표 형식 (원본 5-3 / 4-4 표 병합):
  ```
  ## 무인증/무ACL 배치·관리자 엔드포인트 목록 (N건)
  | Controller | Endpoint | @Session | @Acl | 판정 |
  |-----------|----------|----------|------|------|
  | BatchController | POST /batch/update | ✗ | ✗ | 취약 — 무인증 접근 가능 |
  | AdminController | GET /admin/users | ✓ | ✓ | 양호 |
  | InternalController | POST /internal/sync | ✗ | ✓ (ip) | 확인 필요 — IP ACL만 존재 |
  ```

---

### M2 판정 요약표 (summary_auth.md 「모듈별 판정 요약」에 채움 — 원본 Final Verdict Summary Table 매핑)

| 점검 항목 | 양호 기준 | 취약 기준 |
|---|---|---|
| 배치/관리 API 인증 | @Session + @Acl 모두 적용 | @Session 없음 + @Acl 없음 → 무인증 접근 가능 |
| IDOR | DB WHERE 절이 세션 ID 사용 (sessionMbrId) | DB WHERE 절이 요청 바디 ID 사용 (requestMbrId) → 타인 리소스 접근 |
| IDOR 위험도 — 취소/삭제 | 소유권 검증 후 처리 | 소유권 미검증 → 타인 데이터 파괴 가능 |
| IDOR 위험도 — 개인정보 조회 | 세션 ID 기반 조회 | 파라미터 ID 기반 조회 → 타인 개인정보 열람 가능 |
| IDOR 위험도 — 수정/변경 | 소유권 검증 후 처리 | 소유권 미검증 → 데이터 위변조 |
| ACL (Host Header Spoofing) | Hostname from server-side config | `request.getServerName()` used alone → HTTP Host header trusted |
| ACL (IP — Partial Match) | `split(",")` + `equals()` exact match per IP | `allowedIP.contains(realIP)` — substring bypass possible |
| ACL (regEx) | `matches()` 전체 일치 | `find()`/`containsMatchIn()` 부분 일치 |
| ACL (X-Forwarded-For) | `getRemoteAddr()` in direct-connect env; or X-Forwarded-For validated against trusted proxy range | `getRemoteAddr()` alone in proxy/LB env; or X-Forwarded-For blindly trusted |
| ACL (Env bypass) | ACL enforced in all environments including local/dev | ACL disabled or skipped in local/dev environment |
| ACL (Missing annotation) | All internal/admin/batch APIs protected by `@Acl` or `@PreAuthorize` | Internal API reachable without `@Acl` and without `@Session` |
| ACL (AOP not triggered) | `@Acl` methods include `HttpServletRequest` parameter | `@Acl` present but `HttpServletRequest` missing → AOP cannot intercept |
| ACL (Retention) | `@Retention(RUNTIME)` | RUNTIME 아님 → 전체 `@Acl` 무효 |
| CSRF | CSRF protection enabled; or stateless API with documented justification | `csrf().disable()` without clear justification |
| Unauthenticated access | `permitAll()` scoped to minimum necessary endpoints | Unnecessarily broad `permitAll()` coverage |
