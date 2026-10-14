# 접근제어(ACL) 진단 방법론 (ACL 4-1 ~ 4-4 + 사례/체크리스트)

> **이 파일의 위치와 우선순위**
> - 이 파일은 원본 진단 방법론을 **원문 그대로 보존**한 참조 자료다 (라인 단위 복사, 고객사 식별정보만 익명화).
> - 실행 절차·판정 심각도·출력 형식은 `references/task_prompts/task_26_auth_review.md`가 **우선**한다.
> - 원본의 "Output language", "Final Verdict Summary Table", "Finding Report Format" 지시는
>   task_26 「원본 방법론 출력 지시 매핑」 규칙에 따라 `task26_llm.json` / `summary_auth.md` / `dast_candidates_AUTH.json`으로 매핑된다.
> - 원본 사례(파일명·클래스명·IP·헤더명)는 익명화 예시다. 실제 진단 대상의 이름으로 간주하지 말 것.

> task_26 연결: Section B (B-1 ~ B-4), Section E (DAST 후보)

## Part A — PHASE 4 구조화 절차 (ACL_Analysis)

> 📎 원본: `MySkills/ACL_Analysis.md` L1-242 (원문 보존, 익명화 적용)

### ACL (Access Control) Analysis

> **Output language: Korean**
>
> Analyze the source code directly to detect ACL (Access Control) vulnerabilities and report all findings in the format specified below.
> If no vulnerability is found for a given item, record "이상 없음" (No issue found).
> Perform each step of PHASE 4 in order, then produce the Final Verdict Summary Table at the end.

---

#### PHASE 4. ACL (Access Control)

##### 4-1. Spring Security ACL Analysis

**Target:** `*SecurityConfiguration.java`, `*SecurityConfig.java`

```bash
# Locate Spring Security configuration files
find src -name "*SecurityConfig*" -o -name "*SecurityConfiguration*" -o -name "*WebSecurityConfig*" 2>/dev/null

# Check antMatchers / requestMatchers access control policy
grep -rn "antMatchers\|requestMatchers\|authorizeRequests\|authorizeHttpRequests" src/ --include="*.java" --include="*.kt" -A 5

# Check IP-based access control (hasIpAddress)
grep -rn "hasIpAddress" src/ --include="*.java" --include="*.kt" -A 3

# Check URL patterns accessible without authentication
grep -rn "permitAll\(\)" src/ --include="*.java" --include="*.kt" -B 2 -A 1

# Check CSRF configuration
grep -rn "csrf\(\)\|csrf\.disable\|CsrfConfigurer" src/ --include="*.java" --include="*.kt" -A 3
```

Analysis Instructions:
- Review the access control policy configured in `antMatchers` / `requestMatchers` — identify which URL patterns are permitted and which are restricted
- Identify all `hasIpAddress()` rules and verify they are correctly scoped to admin/internal endpoints only
- Enumerate all `permitAll()` patterns — flag any URL pattern that grants unauthenticated access beyond what is strictly necessary
- If CSRF is disabled, verify whether a documented justification exists (e.g., stateless REST API with JWT) — flag unexplained `csrf().disable()` as a finding

---

##### 4-2. Custom ACL Annotation Analysis

**Target:** Entire source tree

```bash
# Locate custom @Acl annotation definition
grep -rn "@interface Acl\|annotation class Acl" src/ --include="*.java" --include="*.kt" -n

# Find all @Acl, @PreAuthorize, @Secured usages
grep -rn "@Acl\|@PreAuthorize\|@Secured" src/ --include="*.java" --include="*.kt" -n

# Locate AOP Advisor / Aspect that processes the custom ACL annotation
grep -rn "AclAdvisor\|@Aspect.*[Aa]cl\|@Around.*[Aa]cl\|Advisor" src/ --include="*.java" --include="*.kt" -A 10

# Check annotation attributes (ip, host, regEx, etc.)
grep -rn "@Acl(" src/ --include="*.java" --include="*.kt" -A 2

# Check environment-based ACL bypass conditions
grep -rn "local\|dev\|test" src/ --include="*.java" --include="*.kt" -i | grep -i "acl\|skip\|bypass\|disable\|ignore"
grep -rn "profiles\|active\|environment" src/ --include="*.java" --include="*.kt" -A 5 | grep -B 3 "[Aa]cl"
```

Analysis Instructions:
- Locate the custom `@Acl` annotation definition file and review:
  - `@Target` — which elements it can be applied to (method, class, etc.)
  - `@Retention` — whether it is retained at runtime (`RUNTIME` required for AOP to work)
  - Available attributes: `ip`, `host`, `regEx`, etc.
- Locate and read the AOP Advisor / Aspect that processes `@Acl` and understand the enforcement logic
- Check for environment-based ACL bypass:
  - Is ACL enforcement disabled entirely in `local` or `dev` profiles?
  - If yes, verify whether the `dev` server is publicly accessible — flag as elevated risk if so

---

##### 4-3. IP-Based ACL Bypass Vulnerability Analysis

###### Vulnerability 1 — Host Header Spoofing

```bash
# Find @Acl annotations using the host attribute
grep -rn "@Acl(host\|@Acl.*host\s*=" src/ --include="*.java" --include="*.kt" -A 2

# Find getServerName() usage in ACL / security logic
grep -rn "getServerName\(\)" src/ --include="*.java" --include="*.kt" -B 5 -A 3

# Find getHeader("Host") usage
grep -rn "getHeader.*[Hh]ost\|\"Host\"\|'Host'" src/ --include="*.java" --include="*.kt" -B 3 -A 3
```

```java
// Vulnerable — returns the HTTP Host header value, which the attacker controls
return request.getServerName();

// Safe — use server-side configured hostname, not the request header
return serverProperties.getHostname(); // from application config
```

Analysis Instructions:
- Find all controllers or ACL logic that uses the `host` attribute of `@Acl`
- Trace the method that extracts the hostname — if it calls `request.getServerName()`, the value is derived from the HTTP `Host` header, which an attacker can set arbitrarily
- Verify whether sending `Host: [allowed-hostname]` in the request header can bypass the ACL check
- **Verdict: Vulnerable** if the host comparison relies solely on `request.getServerName()` without server-side configuration validation

###### Vulnerability 2 — contains() Partial String Matching

```bash
# Find contains() usage in IP comparison logic
grep -rn "\.contains(realIP\|\.contains(clientIp\|\.contains(remoteAddr\|allowedIP\.contains\|ipList\.contains" \
     src/ --include="*.java" --include="*.kt" -B 3 -A 3

# Broader search: contains() near IP-related variables
grep -rn "\.contains(" src/ --include="*.java" --include="*.kt" -B 2 -A 2 \
     | grep -i "ip\|addr\|host\|allow"
```

```java
// Vulnerable — String.contains() on a comma-separated IP list
if (!allowedIP.contains(realIP)) { ... }
// allowedIP = "10.0.0.1,10.0.0.2"
// realIP = "0.0" → "10.0.0.1,10.0.0.2".contains("0.0") = TRUE → ACL bypassed

// Safe — split and exact-match each IP
val allowedList = allowedIP.split(",").map { it.trim() }
if (!allowedList.contains(realIP)) { ... }
```

Analysis Instructions:
- Locate all IP comparison logic in the ACL implementation
- If `String.contains()` is used to match `realIP` against a comma-separated `allowedIP` string → **Vulnerable** (partial substring bypass possible)
- Verify that exact IP matching is enforced (via `.split(",")` + `.equals()`, or `Arrays.asList(...).contains(realIP)`)
- Note: if `realIP` is obtained via `getRemoteAddr()`, direct TCP-level manipulation is harder — but in load balancer/proxy environments, all traffic arrives from the proxy IP, making this check insufficient on its own

###### Vulnerability 3 — X-Forwarded-For Not Handled

```bash
# Check how the real client IP is extracted
grep -rn "getRemoteAddr\(\)\|X-Forwarded-For\|x-forwarded-for\|X-Real-IP" \
     src/ --include="*.java" --include="*.kt" -B 3 -A 5

# Check whether X-Forwarded-For is trusted / processed
grep -rn "getHeader.*[Ff]orwarded\|getHeader.*X-Real\|RemoteIpFilter\|ForwardedHeaderFilter" \
     src/ --include="*.java" --include="*.kt" -A 3

# Check proxy / load balancer configuration in application properties
grep -rn "server\.forward-headers-strategy\|use-forward-headers\|remoteip\|proxy" \
     . --include="*.properties" --include="*.yml" --include="*.yaml" -i -n
```

Analysis Instructions:
- Identify how the ACL logic extracts the client IP address
- If only `getRemoteAddr()` is used:
  - In a **direct connection** environment → acceptable (TCP-level IP, harder to spoof)
  - In a **proxy / load balancer** environment → `getRemoteAddr()` always returns the proxy IP, making client-level IP ACL ineffective
- If `X-Forwarded-For` header is trusted:
  - Clients can set this header arbitrarily → IP spoofing possible → **Vulnerable** unless the header is validated against known trusted proxy IPs
- Verify whether `RemoteIpFilter` (Tomcat) or `ForwardedHeaderFilter` (Spring) is configured, and whether it restricts trusted proxy IP ranges

---

##### 4-4. Full ACL Coverage Audit

```bash
# Enumerate all @Acl annotation usages with their attributes
grep -rn "@Acl(" src/ --include="*.java" --include="*.kt" -A 2

# Identify internal/batch/admin APIs that may be missing @Acl
grep -rn "@RestController\|@Controller" src/ --include="*.java" --include="*.kt" -l \
     | xargs grep -L "@Acl\|@PreAuthorize\|@Secured" 2>/dev/null

# Find batch / admin / internal endpoint patterns without ACL
grep -rn "@PostMapping\|@GetMapping\|@RequestMapping" src/ --include="*.java" --include="*.kt" -B 5 \
     | grep -B 4 "batch\|admin\|internal\|system\|settle\|cron" \
     | grep -v "@Acl\|@PreAuthorize"

# Verify dual protection: session authentication + IP ACL
grep -rn "@Session\|@Acl" src/ --include="*.java" --include="*.kt" -n \
     | awk -F: '{print $1}' | sort | uniq -c | sort -rn
```

Analysis Instructions:
- Classify all `@Acl` annotation usages by attribute type:
  - `ip` attribute → IP-based restriction → verify bypass vulnerabilities (sections 4-3-2, 4-3-3)
  - `host` attribute → Host header-based restriction → verify Host Header Spoofing (section 4-3-1)
  - `regEx` attribute → regex-based restriction → verify `Pattern.matches()` uses full-string matching (not partial)
- Identify internal / batch / admin APIs that are missing both `@Acl` and `@Session` / `@PreAuthorize`
  - APIs with **neither** annotation → accessible by anyone → **Vulnerable**
  - APIs with `@Acl` but missing `HttpServletRequest` parameter → AOP cannot intercept → effectively no ACL → **Vulnerable**
- Verify dual protection: sensitive APIs should have both session-based authentication **and** IP-based ACL
- Produce a summary table of APIs and their protection status:

```
| Controller | Endpoint | @Session | @Acl | Protection Status |
|-----------|----------|----------|------|------------------|
| BatchController | POST /batch/settle | ✗ | ✗ | 취약 — 무인증 접근 가능 |
| AdminController | GET /admin/users | ✓ | ✓ | 양호 |
| InternalController | POST /internal/sync | ✗ | ✓ (ip) | 확인 필요 — IP ACL만 존재 |
```

---

#### Final Verdict Summary Table

After completing the analysis, fill in the table below and include it in the report.

| Vulnerability | Safe | Vulnerable |
|--------------|------|-----------|
| ACL (Host Header Spoofing) | Hostname from server-side config | `request.getServerName()` used alone → HTTP Host header trusted |
| ACL (IP — Partial Match) | `split(",")` + `equals()` exact match per IP | `allowedIP.contains(realIP)` — substring bypass possible |
| ACL (X-Forwarded-For) | `getRemoteAddr()` in direct-connect env; or X-Forwarded-For validated against trusted proxy range | `getRemoteAddr()` alone in proxy/LB env; or X-Forwarded-For blindly trusted |
| ACL (Env bypass) | ACL enforced in all environments including local/dev | ACL disabled or skipped in local/dev environment |
| ACL (Missing annotation) | All internal/admin/batch APIs protected by `@Acl` or `@PreAuthorize` | Internal API reachable without `@Acl` and without `@Session` |
| ACL (AOP not triggered) | `@Acl` methods include `HttpServletRequest` parameter | `@Acl` present but `HttpServletRequest` missing → AOP cannot intercept |
| CSRF | CSRF protection enabled; or stateless API with documented justification | `csrf().disable()` without clear justification |
| Unauthenticated access | `permitAll()` scoped to minimum necessary endpoints | Unnecessarily broad `permitAll()` coverage |

---

#### Finding Report Format

Write a separate entry in the format below for each vulnerability found.
If no vulnerability is found, state "ACL 취약점 없음".

```
파일 및 위치 (라인 번호):
  예) AclAdvisor.java (45번째 줄)

취약 코드 샘플:
  예) if (!allowedIP.contains(realIP)) {
          throw new AccessDeniedException("IP not allowed");
      }

취약점 근거:
  예) 허용 IP 목록("10.0.0.1,10.0.0.2")을 String.contains()로 비교하여
      "0.0" 같은 부분 문자열로 IP ACL 우회가 가능함.

개선 방안 (수정 코드 예시 포함):
  예) val allowedList = allowedIP.split(",").map { it.trim() }
      if (!allowedList.contains(realIP)) {
          throw new AccessDeniedException("IP not allowed")
      }
```


## Part B — @Acl AOP 구현 분석 보충 (AUTH_VULN_ANALYSIS Step 3)

> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L168-247 (원문 보존, 익명화 적용)

---

### Step 3 — @Acl 어노테이션 분석 (IP 접근 제어)

#### 3-1. AOP 구현 코드 확인

`@Acl`을 처리하는 AOP Advice를 찾아 다음을 확인한다.

**취약 패턴 1: HttpServletRequest 파라미터 의존**

```java
// AclAdviser.java — 취약한 구현
private String getRemoteAddr(JoinPoint joinPoint) {
    Object[] args = joinPoint.getArgs();
    HttpServletRequest request = (HttpServletRequest) Arrays.stream(args)
            .filter(p -> p instanceof HttpServletRequest)
            .findFirst()
            .orElseThrow(() -> new RequestNotFoundException(...));  // ← 예외 발생 → IP 검증 미실행
    return request.getRemoteAddr();
}
```

이 패턴이면 메서드 시그니처에 `HttpServletRequest`가 없을 경우 `@Acl`이 **동작하지 않는다**.

```bash
# @Acl이 선언된 메서드 중 HttpServletRequest 파라미터가 없는 것 찾기
grep -B5 "@Acl" src/ -rn --include="*.kt" | grep -v "HttpServletRequest"
```

**취약 패턴 2: 환경별 ACL 완전 우회**

```java
// local, dev 환경에서 ACL 전체 스킵
if ("local".equals(active) || "dev".equals(active)) {
    return;  // ← 개발 환경에서는 어떤 IP든 통과
}
```

**취약 패턴 3: String.contains() 부분 일치**

```java
// 취약: "192.0.2.76,192.0.2.77".contains("92.0.2.7") → true
if (!allowedIP.contains(realIP)) { throw ... }

// 안전: 정확한 IP 비교
List<String> allowed = Arrays.asList(allowedIP.split(","));
if (!allowed.contains(realIP.trim())) { throw ... }
```

#### 3-2. @Acl 선언 전수 조사

```bash
grep -rn "@Acl" src/ --include="*.kt" --include="*.java"
```

각 선언에 대해:
1. 해당 메서드 시그니처에 `HttpServletRequest request` 파라미터가 있는가?
2. AOP가 `RequestNotFoundException`을 throw하는가, catch하는가?
3. 예외 발생 시 차단되는가, 허용되는가?

#### 3-3. X-Forwarded-For 미처리

로드밸런서/프록시 환경에서 `getRemoteAddr()`는 항상 프록시 IP를 반환한다. 실제 클라이언트 IP 식별 방식과 헤더 위조 가능성을 함께 확인한다.

```bash
grep -rn "X-Forwarded-For\|x-forwarded-for\|getRemoteAddr\|getHeader.*forward" \
  --include="*.java" --include="*.kt" src/
```

| IP 추출 방식 | 환경 | 위험 |
|------------|------|------|
| `getRemoteAddr()` 단독 사용 | 프록시/LB 환경 | 항상 프록시 IP 반환 → IP ACL 무력화 |
| `X-Forwarded-For` 신뢰 | 모든 환경 | 공격자가 헤더 위조로 허용 IP 사칭 가능 |
| `X-Forwarded-For` + 신뢰 프록시 목록 검증 | 권장 | 안전 |

**판단 방법**:
1. 프록시/LB 환경인가? → `getRemoteAddr()` 단독 사용 시 실질적 IP ACL 없음
2. `X-Forwarded-For` 헤더를 그대로 신뢰하는가? → 헤더 위조로 IP 우회 가능

---


## Part C — 익명화 사례 (A-05 ~ A-07)

> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L543-596 (원문 보존, 익명화 적용)

### A-05: `@Acl` AOP 동작 불가

**위치**: `SampleGroupBuyBatchController.kt:32-39`, `AclAdviser.java`

```kotlin
// 취약: HttpServletRequest 파라미터 없음
@Acl(ip = "192.0.2.76,192.0.2.77")
@PostMapping("/settlement")
open fun executeSettlement(
    @PathVariable version: String,
    @RequestParam startTargetDateTime: String?,
    // HttpServletRequest 없음 ← AOP에서 RequestNotFoundException 발생
)
```

```java
// AclAdviser.java — request 없으면 예외 throw
.orElseThrow(() -> new RequestNotFoundException("..."));
// 이 예외가 catch되거나 무시되면 IP 검증 미실행 → 모든 IP 허용
```

**대응방안**: 메서드 시그니처에 `request: HttpServletRequest` 추가. 또는 AOP에서 `RequestContextHolder`로 request 직접 획득하도록 개선.

---

### A-06: String.contains() 부분 IP 우회

**위치**: `AclAdviser.java` — `checkIpAcl()`

```java
// 취약
if (!allowedIP.contains(realIP)) { throw ... }
// "192.0.2.76,192.0.2.77".contains("92.0.2.7") → true (우회 성공)

// 안전
List<String> allowed = Arrays.asList(allowedIP.split(","));
if (!allowed.stream().map(String::trim).collect(toList()).contains(realIP.trim())) { throw ... }
```

---

### A-07: local/dev 환경 ACL 완전 우회

**위치**: `AclAdviser.java`

```java
if ("local".equals(active) || "dev".equals(active)) {
    return;  // ACL 완전 스킵
}
```

개발/알파 환경에서 배치 API에 제한 없이 접근 가능. 스테이징 환경이 외부에 노출된 경우 위험.

---


## Part D — 접근 제어 체크리스트

> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L612-619 (원문 보존, 익명화 적용)

### 접근 제어 체크리스트

- [ ] `@Acl` 어노테이션이 선언된 메서드에 `HttpServletRequest` 파라미터가 있는가?
- [ ] AOP에서 request 추출 실패 시 어떻게 처리하는가? (throw → 차단 or 허용)
- [ ] IP 비교 로직이 정확한 일치 검사를 하는가? (`contains()`가 아닌 `equals()` 또는 split 후 리스트 비교)
- [ ] 환경별 우회 로직(`local`, `dev`)이 운영 환경에서도 적용되지 않는가?
- [ ] 로드밸런서/프록시 환경에서 `getRemoteAddr()`만 사용하는가? (항상 프록시 IP 반환)
- [ ] `X-Forwarded-For` 헤더를 검증 없이 신뢰하는가? (헤더 위조 가능성)
