## Module M0 — auth-recon (인증·인가 구조 파악 → auth_map.json)

**역할**: 이후 모듈(M1~M5)이 "해당 서비스에 존재하는 것만" 점검하도록, 인증·인가 구조와 존재하는 인증 흐름을 먼저 지도화한다.
**실행 조건**: 항상 실행 (모든 모듈의 기반). `--only` 로 일부 모듈만 실행할 때도 M0는 실행하며, 같은 `<prefix>`에 `auth_map.json`이 이미 있으면 아래 「R-7. 재사용 조건」을 만족할 때만 재사용한다.
**입력**: `testbed/<repo>/`, (있으면) `state/<prefix>/api_scan.json`, Phase 1 자산 식별 결과
**출력**: `state/<prefix>/auth_map.json`

> 근거 원본: `methodology/webview_session_methodology.md` 2.1/2.3/3.1/3.3, `methodology/auth_methodology.md` Part A 5-1 / Part B Step 1·Step 9
> 이 모듈은 **판정을 하지 않는다** (finding 생성 금지). 판정은 각 모듈에서 수행한다.

---

### R-1. Repo 유형 판별

| 신호 | 판별 |
|---|---|
| `spring-boot` 의존성, `@RestController`/`@Controller` 존재 | `backend` |
| `com.android.application` 플러그인, `AndroidManifest.xml` | `mobile-client` (Android) |
| `*.xcodeproj`, `Podfile`, `*.swift` 다수 | `mobile-client` (iOS) |
| `pubspec.yaml` | `mobile-client` (Flutter) |
| `package.json`에 `react-native` | `mobile-client` (React Native) |
| `package.json`에 `express`/`passport`/`express-session` | `backend-node` |
| 위 backend/mobile 신호 없이 React/Vue 등 웹 프론트엔드만 존재 | `web-frontend` |
| backend + mobile-client 동시 | `mixed` |

> ⚠️ Android 앱은 `.kt`/`.java` 파일이 있으므로 "`.java`/`.kt` 0건 = 프론트엔드" 규칙만으로 판별하면 백엔드로 오판한다. 반드시 `AndroidManifest.xml`/`com.android.application`을 먼저 확인한다.

```bash
find <src> -name "AndroidManifest.xml" -not -path "*/build/*" | head -3
grep -rln "com.android.application\|com.android.library" <src> --include="*.gradle" --include="*.kts" | head -3
find <src> -maxdepth 3 -name "*.xcodeproj" -o -maxdepth 3 -name "Podfile" -o -maxdepth 3 -name "pubspec.yaml" | head -3
grep -l "react-native\|\"express\"\|passport\|express-session" <src>/package.json 2>/dev/null
grep -rln "spring-boot" <src> --include="*.gradle" --include="*.kts" --include="pom.xml" | head -3
```

### R-2. 기술 스택 식별 (원본 Webview 2.1)

빌드 파일(`build.gradle`, `pom.xml`, `package.json`)로 다음을 기록한다.

| 확인 항목 | 기록 필드 |
|---|---|
| 백엔드 프레임워크 | `stack.framework` |
| API Gateway 존재 여부 (Zuul, Kong, Spring Cloud Gateway, AWS API GW 등) | `stack.gateway` |
| 세션 저장소 (Redis, DB, 인메모리, 외부 서비스 등) | `stack.session_store` |
| 인증 방식 분류 (쿠키/헤더 토큰/JWT/OAuth 2.0/커스텀 토큰) | `stack.auth_type` |
| 모바일 플랫폼 (Android/iOS/Flutter/React Native) | `stack.mobile_platform` |

### R-3. 인증·인가 메커니즘 위치 (판정 없이 위치만)

```bash
grep -rn "@interface\|annotation class" src/ --include="*.java" --include="*.kt" -n
grep -rln "SecurityFilterChain\|WebSecurityConfigurerAdapter\|@EnableWebSecurity" src/ --include="*.java" --include="*.kt"
grep -rln "addInterceptors\|HandlerInterceptor\|InterceptorRegistry" src/ --include="*.java" --include="*.kt"
grep -rln "@Aspect" src/ --include="*.java" --include="*.kt"
grep -rln "HandlerMethodArgumentResolver\|ZuulFilter\|GatewayFilter\|OncePerRequestFilter" src/ --include="*.java" --include="*.kt"
```

기록: 커스텀 인증/인가 어노테이션 이름과 정의 파일, 처리 AOP/Resolver 파일, SecurityConfig 파일, Interceptor 파일, Gateway/Filter 파일. 원본 Webview 3.1의 탐색 순서(① Gateway/Filter → ② AOP/Annotation → ③ 세션 검증 서비스 → ④ DTO(UserInfo 등) → ⑤ Config/Properties)를 따른다.

### R-4. 인증 흐름 인벤토리 (존재 여부 플래그)

각 플래그는 grep 결과 + 해당 파일 1~2개 Read로 확인한다. 키워드만 걸리고 실제 흐름이 아니면 `false`.

| 플래그 | 탐지 신호 (예시) | 연결 모듈 |
|---|---|---|
| `external_session_server` | `session/info`, `auth/validate`, `token/verify`, `checkSession`, 인증용 `RestTemplate`/`WebClient` | M1 |
| `jwt` | `Jwts.parser`, `jwtDecode`, `io.jsonwebtoken`, `nimbus-jose` | M1 (알고리즘/서명 결함은 sec-scan-data) |
| `cookie_session` | `Set-Cookie`, `ResponseCookie`, `CookieManager`, `server.servlet.session` | M1 / M5 |
| `test_session_bypass_signal` | `TEST_ID`, `startsWith.*ID`, `mock.*session`, `testSession` | M1 |
| `pin_step_up` | `pinConfirmationDate`, `passwordConfirmationDate`, `pinStatus`, `pinVerified` | M3 |
| `mfa_otp` | `otp`, `totp`, `mfa`, `2fa`, `twoFactor`, `certNo`, `authNo`, `verifyCode`, `verificationCode`, `smsAuth`, `sendSms`, `인증번호` | M3 |
| `payment_or_quota` | `pay`, `purchase`, `charge`, `refund`, `point`, `coupon`, `order`, `issue`, 수량/횟수 제한 | M3 / M4 |
| `batch_admin` | `*Batch*Controller*`, `*Admin*Controller*`, `*Internal*Controller*`, `*Manage*Controller*`, `@Scheduled` | M2 / M4 |
| `ip_acl` | `@Acl`, `hasIpAddress`, `allowedIP`, `getRemoteAddr`, `X-Forwarded-For` | M2 |
| `spring_security_rules` | `antMatchers`, `requestMatchers`, `authorizeRequests`, `authorizeHttpRequests` | M2 |
| `resource_id_params` | `@PathVariable`/`@RequestParam` 중 `mbrId`, `userId`, `seq`, `histSeq`, `orderId`, `itemId`, `accountId` | M2 |
| `redis_guard_signal` | `redisTemplate`, `redisService`, `setnx`, `tryLock`, `Redisson` | M4 |
| `webview_server_side` | `x-.*session` 헤더 키, Native→Webview 헤더 주입 전제 헤더 처리 | M1 / M5 |
| `webview_client_side` | `loadUrl`, `extraHeaders`, `addJavascriptInterface`, `evaluateJavascript`, `WKScriptMessageHandler`, `CookieManager` | M5 |

### R-5. 민감 엔드포인트 인벤토리 (토큰 절약형)

- `api_scan.json`이 있으면 그것을 기준으로, 없으면 `@*Mapping` grep으로 만든다.
- **전체 엔드포인트를 저장하지 말고** 아래 태그 중 하나 이상에 해당하는 엔드포인트만 `endpoints[]`에 기록한다.
  - 태그: `payment`, `cancel_delete`, `pii`, `modify`, `batch_admin`, `internal`, `otp`, `pin`, `state_change_get`(상태를 바꾸는 GET), `resource_id`
- 엔드포인트별 기록: `method`, `path`, `controller`(Class.method), `file`, `line`, `auth_annotation`(`@Session(required=true|false)`/`@PreAuthorize`/없음/확인불가), `acl_annotation`, `tags[]`

### R-6. 모듈 실행 계획 결정

| 모듈 | 실행 조건 | skip 시 기록 |
|---|---|---|
| M1 authn | repo 유형이 `backend`/`backend-node`/`mixed` | "해당없음(백엔드 아님)" |
| M2 authz-acl | 위와 동일 (IDOR는 모든 백엔드 공통). B-2/B-3(IP ACL)은 `ip_acl=false`이면 해당 절만 "해당없음" | 동일 |
| M3 stepup-mfa | `pin_step_up` 또는 `mfa_otp` 또는 `payment_or_quota` 중 하나라도 `true` | "해당없음(PIN/2차인증/결제 흐름 없음)" |
| M4 logic-race | `payment_or_quota` 또는 `batch_admin` 또는 `redis_guard_signal` 또는 `state_change_get` 엔드포인트 존재 | "해당없음(금전/수량/배치 흐름 없음)" |
| M5 webview-client | `mobile-client`/`mixed`이거나, `webview_server_side`/`webview_client_side` 중 하나라도 `true`, 또는 M1 A-6에서 Native App + Webview 구조 확인 | "해당없음(Webview 구조 없음)" |

- repo 유형 `web-frontend` → 전 모듈 skip, 결과에 "해당없음(프론트엔드 repo)" 기록 (기존 규칙 유지).
- repo 유형 `mobile-client` → **M5만 실행** (M1~M4는 서버 측 관심사).
- 사용자가 `--only`로 모듈을 지정하면 지정 모듈만 실행하되, 실행 조건 미충족 모듈은 "해당없음(조건 미충족)" 기록 후 skip.

### auth_map.json 스키마

```json
{
  "repo": "<repo>",
  "generated_at": "ISO8601",
  "source": "static-code",
  "source_ref": { "repo_commit": "<git HEAD sha 또는 null>", "source_hash": "<sha256 또는 null>", "scope": "<DIAGNOSIS_SCOPE 또는 전체>" },
  "repo_type": "backend|backend-node|mobile-client|web-frontend|mixed",
  "stack": {
    "framework": "", "gateway": "", "session_store": "",
    "auth_type": "", "mobile_platform": ""
  },
  "mechanisms": {
    "custom_annotations": [{ "name": "@Session", "definition_file": "", "processor_file": "" }],
    "security_config_files": [],
    "interceptor_files": [],
    "gateway_filter_files": [],
    "argument_resolver_files": []
  },
  "flows": {
    "external_session_server": false, "jwt": false, "cookie_session": false,
    "test_session_bypass_signal": false, "pin_step_up": false, "mfa_otp": false,
    "payment_or_quota": false, "batch_admin": false, "ip_acl": false,
    "spring_security_rules": false, "resource_id_params": false,
    "redis_guard_signal": false, "webview_server_side": false, "webview_client_side": false
  },
  "flow_evidence": { "<flag>": ["file:line", "..."] },
  "endpoints": [
    {
      "method": "POST", "path": "/api/v1/order/cancel", "controller": "OrderController.cancel()",
      "file": "src/.../OrderController.kt", "line": 88,
      "auth_annotation": "@Session(required=true)", "acl_annotation": null,
      "tags": ["cancel_delete", "resource_id"]
    }
  ],
  "module_plan": {
    "M1": { "run": true,  "reason": "" },
    "M2": { "run": true,  "reason": "" },
    "M3": { "run": false, "reason": "해당없음(PIN/2차인증/결제 흐름 없음)" },
    "M4": { "run": true,  "reason": "" },
    "M5": { "run": false, "reason": "해당없음(Webview 구조 없음)" }
  },
  "script_skip_args": ["pin"]
}
```

`script_skip_args`는 Auto-Scan 실행 시 `--skip`에 공백 구분으로 그대로 전달한다 (예: `--skip pin toctou`, 빈 배열이면 `--skip` 생략). 모듈 ↔ 스크립트 항목 매핑은 SKILL.md 참조.
- `run == false`인 모듈의 항목을 모두 넣는다 (M1: `session testbypass` / M2: `idor permitall ipacl aclcoverage` / M3: `pin` / M4: `toctou`).
- M2를 실행하더라도 `flows.ip_acl == false`이면 `ipacl`을 넣는다.
- 허용값은 스크립트 `--skip` choices(`session`, `testbypass`, `pin`, `idor`, `permitall`, `ipacl`, `aclcoverage`, `toctou`)만 사용한다.

**`source` — 맵의 출처** (v2 추가)

| 값 | 뜻 | 현재 |
|---|---|---|
| `static-code` | 이 모듈이 소스코드에서 생성 | **이 skill이 쓰는 유일한 값** |
| `openapi-spec` | API 명세에서 생성 | 예약 (생성기 없음) |
| `behavioral-observed` | 소스 없이 관찰로 생성 | 예약 (생성기 없음) |
| `mixed` | 둘 이상을 병합 | 예약 |

- 하위 모듈(M1~M5)의 판정 기준은 소스코드 근거를 전제로 한다. `source != "static-code"`인 맵을 받으면 모듈 실행 계획(`module_plan`)만 참고하고, `code-confirmed` 판정은 코드를 Read로 확인한 항목에만 부여한다.
- 예약 값은 향후 다른 recon 수단이 같은 스키마로 맵을 만들 수 있게 자리만 잡아 둔 것이다.

### R-7. 재사용 조건 (stale 방지)

같은 `<prefix>`에 `auth_map.json`이 있을 때, 아래를 **모두** 만족하면 재사용하고 하나라도 다르면 M0를 다시 실행한다.

1. `source == "static-code"`
2. `source_ref.repo_commit`이 현재 `testbed/<repo>`의 `git rev-parse HEAD`와 같다
3. `.git`이 없어 커밋을 알 수 없으면 `source_ref.source_hash`가 현재 값과 같다
4. `source_ref.scope`가 이번 실행의 `DIAGNOSIS_SCOPE`와 같다

```bash
git -C testbed/<repo> rev-parse HEAD 2>/dev/null
# .git이 없을 때: 진단 대상 소스 파일(경로+내용) 해시
find testbed/<repo> -type f \( -name "*.java" -o -name "*.kt" -o -name "*.yml" -o -name "*.yaml" -o -name "*.properties" -o -name "*.xml" -o -name "*.gradle" -o -name "*.kts" \) -not -path "*/build/*" -print0 | sort -z | xargs -0 sha256sum | sha256sum
```

- 재생성 시 완료 출력에 `[M0] auth_map.json 재생성 — 사유: repo_commit 변경 (<old> → <new>)` 한 줄을 남긴다.
- 커밋·해시 둘 다 구할 수 없으면 재사용하지 않고 항상 재생성한다.
- 재사용 시 완료 출력에 `[M0] auth_map.json 재사용 — repo_commit <sha> 일치`를 남긴다.

### 완료 출력

```
[M0 auth-recon] auth_map.json 생성 완료
  repo_type : backend
  flows     : pin_step_up, payment_or_quota, batch_admin, ip_acl, redis_guard_signal
  모듈 계획 : M1 ✓ | M2 ✓ | M3 ✓ | M4 ✓ | M5 ✗(Webview 구조 없음)
```
