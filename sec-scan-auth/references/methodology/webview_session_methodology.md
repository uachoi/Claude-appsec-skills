# Webview 인증 및 세션 관리 진단 방법론 (Native App ↔ Webview)

> **이 파일의 위치와 우선순위**
> - 이 파일은 원본 진단 방법론을 **원문 그대로 보존**한 참조 자료다 (라인 단위 복사, 고객사 식별정보만 익명화).
> - 실행 절차·판정 심각도·출력 형식은 `references/task_prompts/task_26_auth_review.md`가 **우선**한다.
> - 원본의 "Output language", "Final Verdict Summary Table", "Finding Report Format" 지시는
>   task_26 「원본 방법론 출력 지시 매핑」 규칙에 따라 `task26_llm.json` / `summary_auth.md` / `dast_candidates_AUTH.json`으로 매핑된다.
> - 원본 사례(파일명·클래스명·IP·헤더명)는 익명화 예시다. 실제 진단 대상의 이름으로 간주하지 말 것.

> task_26 연결: Section D (D-1 ~ D-8), Section E (DAST 후보)
> 실행 조건: Auth 5-6에서 Native App + Webview 구조가 확인되었거나, 진단 대상이 모바일 앱/웹뷰 클라이언트 repo인 경우

## Part A — Webview 인증·세션 분석 방법론 (WEBVIEW_SESSION_ANALYSIS)

> 📎 원본: `MySkills/WEBVIEW_SESSION_ANALYSIS.md (= 5. webview-auth-session-analysis.md, 동일 파일)` L1-627 (원문 보존, 익명화 적용)

### Webview 인증 및 세션 관리 분석 방법론
> Mobile App ↔ Webview 세션 공유 메커니즘 보안 점검 가이드

---

#### 1. 개요 및 목적

##### 1.1 분석 목적
모바일 앱에서 Webview 기반 서비스를 제공할 때 발생하는 인증·세션 관리 흐름을 분석하고, 보안 취약점을 식별한다.

##### 1.2 분석 범위
| 구분 | 내용 |
|------|------|
| 분석 대상 | Native App ↔ Webview 간 세션 공유 메커니즘 |
| 분석 시나리오 | ① 비로그인 → 로그인 → Webview 진입 / ② 로그인 상태 → Webview 진입 |
| 분석 관점 | 세션 출처, 전달 방식, 자동 로그인, 토큰 유효성, 보안 취약점 |

---

#### 2. 사전 준비

##### 2.1 기술 스택 식별 (분석 착수 전 필수)

빌드 파일(`build.gradle`, `pom.xml`, `package.json`)로 다음을 먼저 파악한다.

| 확인 항목 | 확인 방법 |
|---------|---------|
| 백엔드 프레임워크 | 빌드 파일 dependencies 섹션 |
| API Gateway 존재 여부 | Zuul, Kong, Spring Cloud Gateway, AWS API GW 등 |
| 세션 저장소 | Redis, DB, 인메모리, 외부 서비스 등 |
| 인증 방식 분류 | 쿠키/헤더 토큰/JWT/OAuth 2.0/커스텀 토큰 |
| 모바일 플랫폼 | Android(Java/Kotlin) / iOS(Swift/Obj-C) / Flutter / React Native |

##### 2.2 분석 도구 준비

```
정적 분석:  소스코드 에디터, grep/ripgrep
동적 분석:  Burp Suite / OWASP ZAP (HTTPS 프록시)
모바일:     Android Studio Logcat / Xcode Console
            Frida (동적 계측, 필요 시)
```

##### 2.3 초기 탐색용 grep 키워드

```bash
# 인증/세션 관련
grep -r "session" --include="*.java" --include="*.kt" -l
grep -r "token" --include="*.java" --include="*.kt" -l
grep -r "cookie" --include="*.java" --include="*.kt" -l
grep -r "jwt" -i --include="*.java" --include="*.kt" -l
grep -r "oauth" -i --include="*.java" --include="*.kt" -l

# 헤더 키 이름 파악
grep -r "getHeader\|addHeader\|setHeader" --include="*.java" --include="*.kt"

# 설정 파일에서 세션 키 이름 확인
grep -r "session.key\|session-key\|sessionKey" --include="*.properties" --include="*.yml"
```

---

#### 3. 정적 분석 방법

##### 3.1 핵심 파일 탐색 순서

인증 흐름은 다음 계층 순서로 추적한다.

```
① Gateway / Filter 계층
   → 요청 전처리, 헤더 추가/변환
   → 찾을 파일: *Filter.java, *Interceptor.java, *PreFilter.java

② AOP / Annotation 계층
   → 세션/토큰을 컨트롤러 메서드에 주입하는 방식
   → 찾을 파일: *Advisor.java, *Aspect.java, @Session, @Auth 등 커스텀 어노테이션

③ 세션 검증 서비스 계층
   → 외부 서비스 호출 또는 로컬 검증 로직
   → 찾을 파일: *SessionService, *AuthService, *RestTemplate (인증용)

④ DTO 계층
   → 세션 검증 후 컨트롤러에 전달되는 사용자 정보 구조
   → 찾을 파일: UserInfo, SessionInfo, AuthInfo 등

⑤ Config / Properties 계층
   → 헤더 키 이름, 외부 서비스 URL, 타임아웃 설정
   → 찾을 파일: *.properties, *.yml, constants*.java
```

##### 3.2 흐름 추적 방법

**① 헤더 키 이름 확인**
```bash
# properties/yml에서 세션 헤더 키 이름 탐색
grep -r "header.*session\|session.*header\|header.*token\|token.*header" \
  --include="*.properties" --include="*.yml"
```

**② 헤더 추출 지점 확인**
```bash
grep -r "getHeader" --include="*.java" --include="*.kt" -n
```
→ 추출된 헤더 값이 어디로 전달되는지 호출 스택을 역방향으로 추적

**③ 외부 세션 검증 엔드포인트 확인**
```bash
grep -r "session/info\|session/validate\|session/verify\|token/validate" \
  --include="*.java" --include="*.kt" --include="*.properties" --include="*.yml"
```

**④ 인증 레벨(Role/Scope) 분기 확인**
```bash
grep -r "accountType\|acctTpCd\|role\|scope\|authority" \
  --include="*.java" --include="*.kt" -n
```

##### 3.3 세션 검증 방식 분류

코드에서 아래 패턴 중 어디에 해당하는지 확인한다.

| 유형 | 특징 | 확인 포인트 |
|------|------|-----------|
| **로컬 검증** | JWT 서명 검증, 만료일 파싱 | `Jwts.parser()`, `jwtDecode()`, exp claim |
| **외부 서비스 검증** | 별도 인증 서버에 HTTP 요청 | `RestTemplate`, `WebClient` + 세션 검증 URL |
| **DB 조회 검증** | 세션 테이블 직접 조회 | `SessionRepository`, `SELECT * FROM session` |
| **캐시 검증** | Redis/EHCache에서 세션 조회 | `redisTemplate.get`, `cacheManager` |

---

#### 4. Native App ↔ Webview 세션 전달 메커니즘

##### 4.1 전제: Native App과 Webview는 별개의 컨텍스트

일반 브라우저와 달리 Native App 내부의 Webview는 **앱 코드가 HTTP 요청을 제어할 수 있다.**

```
일반 브라우저 (Chrome, Safari)
  └─ 사용자가 임의로 HTTP 헤더를 추가할 방법 없음
     → 서버가 발급한 쿠키를 자동으로 붙이는 것만 가능

Native App 안의 Webview
  └─ 앱 코드가 Webview에 헤더를 직접 주입 가능
     → "이 세션 ID를 요청에 붙여라" 라고 앱이 지시할 수 있음
```

따라서 Webview는 자체적으로 로그인 상태를 알지 못하고,
**앱이 세션 토큰을 Webview에 전달해줘야 서버가 인증된 사용자로 인식한다.**

##### 4.2 세션 토큰 저장 위치 (앱 사이드)

로그인 완료 후 서버에서 발급받은 세션 토큰을 앱이 보관하는 방식이다.

| 저장소 | 특징 | 보안 수준 |
|--------|------|---------|
| **메모리 (RAM)** | 앱 실행 중에만 유지. 앱 종료 시 사라짐. 전역변수/Singleton에 보관 | 낮음 (프로세스 덤프로 노출 가능) |
| **SharedPreferences (Android) / UserDefaults (iOS)** | 파일로 저장. 앱 재실행 후에도 유지. 암호화 없이 평문 저장 | 낮음 (루팅/탈옥 기기에서 파일 직접 읽기 가능) |
| **EncryptedSharedPreferences (Android) / Keychain (iOS)** | OS가 AES256으로 암호화하여 보관. 하드웨어 보안 모듈 연동 | 높음 (SecureStorage) |
| **외부 저장소 (SD카드 등)** | 다른 앱도 접근 가능 | 매우 낮음 (토큰 저장에 부적합) |

**코드 탐색 방법:**
```bash
# Android
grep -r "SharedPreferences\|EncryptedSharedPreferences\|Keystore" \
  --include="*.java" --include="*.kt"

# iOS
grep -r "UserDefaults\|SecItemAdd\|Keychain" \
  --include="*.swift" --include="*.m"

# Flutter / React Native
grep -r "flutter_secure_storage\|AsyncStorage\|SecureStore" \
  --include="*.dart" --include="*.js" --include="*.ts"
```

**분석 포인트:**
```
[ ] 세션 토큰이 평문 저장소(SharedPreferences/UserDefaults)에 저장되는지
[ ] 암호화 저장소(Keychain/EncryptedSharedPreferences)를 사용하는지
[ ] 메모리에만 보관 시 앱 재실행 후 세션 유지 여부
[ ] 로그아웃 시 저장소에서 토큰이 삭제되는지
```

##### 4.3 Native → Webview 토큰 전달 방식 분류

서비스마다 아래 방식 중 하나 또는 복합적으로 사용한다. 분석 시 반드시 어떤 방식인지 식별한다.

---

###### 방식 1: HTTP 헤더 직접 주입 (extraHeaders)

앱 코드가 Webview의 첫 페이지 로드 시 HTTP 요청 헤더에 세션 토큰을 직접 끼워 넣는다.

```java
// Android 예시
String sessionId = secureStorage.get("session_id");  // 저장소에서 꺼냄

Map<String, String> headers = new HashMap<>();
headers.put("x-session-id", sessionId);              // 헤더 Map 구성

webView.loadUrl("https://webview.service.com/home", headers);
// 이 순간 Webview가 보내는 실제 HTTP 요청:
//
//   GET /home HTTP/1.1
//   Host: webview.service.com
//   x-session-id: abc123...    ← 앱이 주입한 헤더
```

**중요한 제약 — 최초 로드에만 적용됨:**
```
webView.loadUrl(url, headers) 호출
  └─ 첫 페이지 요청: GET /home  → 헤더 포함 ✓

이후 Webview 내부에서 발생하는 추가 요청
  ├─ JavaScript fetch("/api/user")  → 헤더 없음 ✗
  ├─ 페이지 내 링크 클릭           → 헤더 없음 ✗
  └─ XMLHttpRequest                → 헤더 없음 ✗
```

이 제약을 해결하는 방법:
```
해결책 A: shouldInterceptRequest 사용
  → WebViewClient를 오버라이드하여 모든 요청을 가로채고
    헤더를 강제로 추가 후 재전송

해결책 B: JavaScript Bridge로 토큰을 JS에 전달
  → JS 코드가 fetch() 호출 시 헤더를 직접 포함

해결책 C: 쿠키로 전환
  → loadUrl 전에 CookieManager로 쿠키를 심어두면
    이후 모든 요청에 자동으로 쿠키가 포함됨
```

**코드 탐색:**
```bash
grep -r "loadUrl\|extraHeaders" --include="*.java" --include="*.kt"
grep -r "shouldInterceptRequest" --include="*.java" --include="*.kt"
```

- **보안 장점**: URL에 토큰 미노출
- **보안 주의**: 헤더가 해당 도메인의 모든 서브도메인으로도 전송될 수 있음

---

###### 방식 2: URL 파라미터 전달

```kotlin
val url = "https://webview.service.com/page?token=$sessionToken"
webView.loadUrl(url)
```

**보안 위험:**
```
토큰이 URL에 노출되므로:
  - 서버 접근 로그에 토큰 평문 기록
  - 브라우저 히스토리에 기록
  - Referer 헤더로 외부 도메인에 유출 가능
  - 화면 캡처/공유 시 노출
```

**코드 탐색:**
```bash
grep -rn "loadUrl.*token\|loadUrl.*session\|loadUrl.*auth" \
  --include="*.java" --include="*.kt" --include="*.swift"
```

---

###### 방식 3: JavaScript Bridge (JavascriptInterface)

앱이 JS에서 호출 가능한 Native 함수를 노출하여 토큰을 전달한다.

```java
// Android: Native 코드
webView.addJavascriptInterface(new Object() {
    @JavascriptInterface
    public String getToken() {
        return sessionId;  // JS에서 NativeBridge.getToken() 으로 호출
    }
}, "NativeBridge");

// Webview의 JavaScript에서
const token = NativeBridge.getToken();
fetch("/api/user", { headers: { "x-session-id": token } });
```

**보안 위험:**
```
addJavascriptInterface로 등록된 메서드는
페이지 내의 모든 JavaScript에서 호출 가능
→ XSS 취약점 발생 시 토큰 탈취 가능
→ Android 4.2 미만: 원격 코드 실행(RCE) 가능 (CVE-2012-6636)
```

**코드 탐색:**
```bash
grep -r "addJavascriptInterface\|@JavascriptInterface\|WKScriptMessageHandler" \
  --include="*.java" --include="*.kt" --include="*.swift"
```

---

###### 방식 4: 쿠키 공유

loadUrl 전에 CookieManager로 쿠키를 심어두면 이후 모든 Webview 요청에 자동으로 포함된다.

```java
// Android: 쿠키 주입
CookieManager cookieManager = CookieManager.getInstance();
cookieManager.setCookie("https://webview.service.com", "SESSION=" + sessionId);
cookieManager.flush();

webView.loadUrl("https://webview.service.com/home");
// 이후 모든 요청에 Cookie: SESSION=abc123... 자동 포함
```

**확인 포인트:**
```
[ ] 쿠키 속성 확인
    - HttpOnly: JS에서 document.cookie로 읽지 못하게 차단
    - Secure: HTTPS에서만 전송
    - SameSite: CSRF 방어 (Strict / Lax / None)
    - Domain: 쿠키 적용 범위 (서브도메인 포함 여부)
    - Expires/Max-Age: 만료 시간
```

**코드 탐색:**
```bash
grep -r "CookieManager\|setCookie\|NSHTTPCookieStorage\|HTTPCookieStore" \
  --include="*.java" --include="*.kt" --include="*.swift"
```

---

###### 방식 5: evaluateJavascript / PostMessage

앱이 Webview 로드 후 JavaScript를 직접 실행하여 토큰을 주입한다.

```java
// Android: Webview 로드 완료 후 JS 실행
webView.evaluateJavascript(
    "window.__sessionToken = '" + sessionId + "';",
    null
);
// 또는 postMessage로 전달
webView.evaluateJavascript(
    "window.postMessage({type:'AUTH', token:'" + sessionId + "'}, '*');",
    null
);
```

**보안 위험:**
```
window 전역 변수로 토큰 노출 시
→ XSS 취약점 발생 시 window.__sessionToken 으로 즉시 탈취 가능
```

**코드 탐색:**
```bash
grep -r "evaluateJavascript\|evaluateScript\|postMessage" \
  --include="*.java" --include="*.kt" --include="*.swift"
```

---

##### 4.4 공통 흐름도

```
[Native App]
     │
     │ 로그인 (Native UI or WebAuth)
     ▼
[인증 서버 / 세션 서버]
     │
     │ 세션 토큰 발급
     │ → 앱 저장소에 보관 (4.2 참조)
     ▼
[Webview 진입]
     │
     │ 세션 토큰 전달 (4.3의 방식 1~5 중 해당 방식으로)
     ▼
[Webview API 서버]
     │
     │ 세션 유효성 검증 (3.3의 방식으로)
     ▼
[인증 레벨 확인 → 서비스 실행]
```

##### 4.5 시나리오 A: 비로그인 → 로그인 → Webview 진입

분석 포인트:

```
1. 로그인 완료 응답에서 토큰/세션 ID 발급 위치 확인
   → 응답 바디(JSON 필드명)? 응답 헤더(Set-Cookie, x-token)?

2. 앱이 발급된 토큰을 어디에 저장하는지 확인 (4.2 기준)
   → 평문 저장 여부 확인

3. Webview 열기 직전, 토큰을 어떻게 Webview에 전달하는지 확인
   → 4.3의 방식 1~5 중 어느 것인지 식별

4. Webview 첫 API 호출 시 서버 측 세션 검증 흐름 확인
   → 토큰 신규 검증? 기존 세션 재사용?

5. 인증 레벨(role, scope, acctTpCd 등) 요구 여부 확인
   → 비로그인 상태로는 접근할 수 없는 API가 존재하는지
```

##### 4.6 시나리오 B: 로그인 상태 → Webview 진입

분석 포인트:

```
1. 앱이 보유한 세션 토큰의 유효성을 진입 전 확인하는지
   → 사전 체크 없이 그냥 전달? vs 만료 체크 후 갱신?

2. 세션 만료 시 서버 응답 코드와 앱 처리 방식
   → 401/403 반환 후 재로그인 유도?
   → 자동 토큰 갱신(refresh) 메커니즘 존재 여부?

3. refreshYn, reissue 등 토큰 갱신 파라미터 존재 여부
   → API 파라미터 or 별도 /refresh 엔드포인트

4. 긴 세션 유지 정책 (세션 타임아웃 설정값 확인)
   → 설정 파일에서 session.timeout, expiry 값 확인
```

---

#### 5. 항목별 분석 체크리스트

##### 5.1 세션/쿠키를 어디서 가져오는지 (출처)

```
[ ] 로그인 API 응답에서 세션 토큰 발급 위치 확인
    → 응답 바디 JSON 필드명 기록
    → 응답 헤더 이름 기록 (Set-Cookie, x-session-id 등)

[ ] 서버 사이드 세션 저장소 파악
    → Redis, DB, 인메모리, 외부 인증 서버 중 어디인지

[ ] 클라이언트 저장 위치 파악 (4.2 기준)
    → 평문 저장(SharedPreferences/UserDefaults) 여부 확인
    → SecureStorage(Keychain/EncryptedSharedPreferences) 사용 여부

[ ] 쿠키 기반이라면 쿠키 속성 확인
    → HttpOnly, Secure, SameSite, Domain, Path, Expires
```

##### 5.2 Native ↔ Webview 인증 정보 전달 방식

```
[ ] 전달 방식 식별 (4.3의 방식 1~5 중 어느 것인지)

[ ] 전달되는 인증 데이터 항목 기록
    → 세션 ID / 액세스 토큰 / 사용자 ID / CI / 기타

[ ] 전달 대상 도메인 범위 확인
    → 메인 도메인만? 서브도메인 포함? 외부 도메인?

[ ] 방식 1(extraHeaders) 사용 시: 최초 로드 이후 요청 처리 방식 확인
    → shouldInterceptRequest? JS Bridge? 쿠키 병행?
```

##### 5.3 자동 로그인(SSO-like) 구조 구현 방식

```
[ ] 토큰 전달만으로 자동 인증이 되는 구조인지 확인
    → 별도 로그인 페이지 없이 API 호출 가능 여부

[ ] 별도 토큰 교환(Token Exchange) 엔드포인트 존재 여부
    → 예: 앱 토큰 → Webview 전용 단기 토큰 발급

[ ] 세션 공유 범위 확인
    → Native App 세션과 Webview 세션이 동일한지, 분리되는지

[ ] 인증 실패 시 동작 확인
    → Webview 내 로그인 페이지로 리다이렉트?
    → Native App으로 콜백 후 재로그인?
```

##### 5.4 앱 저장 토큰 사용 vs 서버에서 세션 재발급

```
[ ] 앱이 보유한 토큰을 그대로 Webview에 전달하는지 확인

[ ] Webview 진입 시 새 토큰/세션을 서버에서 재발급하는지 확인
    → 재발급 엔드포인트 존재 여부

[ ] 토큰 갱신(refresh) 메커니즘 존재 여부
    → refresh_token, refreshYn 파라미터, /refresh 엔드포인트

[ ] 토큰 유효 기간 정책 확인
    → 설정 파일의 timeout, expiry, ttl 값
```

##### 5.5 토큰 유효성 확인 방법

```
[ ] 검증 방식 분류 (3.3의 유형 확인)
    → 로컬(JWT) / 외부 서비스 호출 / DB 조회 / 캐시

[ ] 검증 주체 확인
    → 클라이언트 사이드만? 서버 사이드만? 양쪽?

[ ] 검증 실패 응답 코드 및 메시지 확인
    → HTTP 상태 코드 (401, 403)
    → 에러 코드 체계 (커스텀 코드)

[ ] 검증 실패 후 클라이언트 처리 방식
    → 자동 재시도? 재로그인 유도? 세션 갱신 시도?

[ ] 세션 검증 API 호출 빈도
    → 매 요청마다? 최초 1회? 캐싱 여부?
```

##### 5.6 보안 취약 포인트 식별

```
[ ] 토큰 전송 채널 보안
    → HTTPS 강제 여부 (HTTP 허용 여부)
    → 인증서 피닝 적용 여부

[ ] 토큰 저장 보안 (4.2 기준)
    → 평문 저장소(SharedPreferences/UserDefaults) 사용 여부
    → SecureStorage(Keychain/EncryptedSharedPreferences) 사용 여부

[ ] 토큰 노출 경로 확인
    → URL 파라미터로 전달 시 로그/히스토리 노출 (방식 2)
    → 서버 접근 로그에 토큰 기록 여부

[ ] JavaScript Bridge 노출 범위 (방식 3 사용 시)
    → addJavascriptInterface 대상 도메인 제한 여부
    → @JavascriptInterface 메서드의 최소 권한 원칙 적용 여부
    → Android 4.2 미만 지원 여부 (RCE 취약점 CVE-2012-6636)

[ ] evaluateJavascript 사용 시 (방식 5)
    → window 전역 변수로 토큰 노출 여부
    → XSS 발생 시 토큰 탈취 가능성

[ ] 테스트/개발 환경 우회 코드 잔존 여부
    → profile 분기로만 차단된 테스트 세션 우회
    → 하드코딩된 테스트 계정/토큰

[ ] CSRF 설정 확인
    → CSRF 비활성화 여부 및 API 전용 서버 여부

[ ] 내부 API 외부 접근 차단 확인
    → /internal, /admin 경로의 접근 제어 방식
    → URI prefix 매칭만 사용 시 우회 가능성

[ ] 토큰/세션 ID 예측 가능성
    → 랜덤성 부족 여부 (순차 발급, 짧은 길이)

[ ] 로그 민감 정보 노출
    → 세션 ID, 사용자 개인 식별 정보가 서버 로그에 평문 기록 여부
```

---

#### 6. 발견사항 기록 템플릿

분석 완료 후 아래 표를 채워 정리한다.

##### 6.1 인증 방식 요약

| 항목 | 발견값 | 비고 |
|------|--------|------|
| 세션 토큰 헤더 키 이름 | | |
| 세션 검증 방식 | 로컬 / 외부서비스 / DB / 캐시 | |
| 쿠키 사용 여부 | 사용 / 미사용 | |
| JWT 사용 여부 | 사용 / 미사용 | |
| 토큰 갱신(refresh) 여부 | 있음 / 없음 | |
| 인증 레벨 분류 체계 | | 코드값 목록 |
| 세션 검증 외부 서비스 URL | | |

##### 6.2 Native → Webview 전달 방식

| 항목 | 발견값 |
|------|--------|
| 전달 방식 (4.3 기준 방식 번호) | |
| 앱 토큰 저장 위치 (4.2 기준) | |
| 전달되는 데이터 항목 | |
| 최초 로드 이후 요청 처리 방식 | |

##### 6.3 보안 취약점 발견 목록

| 번호 | 취약점 | 위치(파일/엔드포인트) | 위험도 | 설명 |
|------|--------|---------------------|--------|------|
| 1 | | | 상/중/하 | |
| 2 | | | | |

---

#### 7. 분석 참고: 기술 스택별 주요 탐색 포인트

##### Spring Boot (Java/Kotlin)
| 구성요소 | 역할 | 파일 패턴 |
|---------|------|---------|
| Zuul / Spring Cloud Gateway Filter | 요청 전처리, 헤더 주입 | `*PreFilter.java`, `*GatewayFilter` |
| Spring AOP Advisor/Aspect | 세션 자동 검증·주입 | `*Advisor.java`, `*Aspect.java` |
| HandlerMethodArgumentResolver | 파라미터 자동 주입 | `*Resolver.java` |
| Spring Security | 경로별 인증 설정 | `*SecurityConfiguration.java` |
| RestTemplate / WebClient | 외부 검증 서비스 호출 | `*RestTemplate.java` |

##### Node.js (Express)
| 구성요소 | 역할 | 파일 패턴 |
|---------|------|---------|
| Express Middleware | 요청 전처리 | `auth.middleware.js`, `session.middleware.js` |
| Passport.js | 인증 전략 | `passport.config.js` |
| express-session / cookie-session | 세션 관리 | `app.js` 내 `session()` 설정 |

##### 공통 탐색 패턴
```bash
# 세션 검증 로직 탐색
grep -rn "sessionId\|session_id\|accessToken\|access_token" \
  --include="*.java" --include="*.kt" --include="*.js" --include="*.ts"

# 토큰 만료 처리 탐색
grep -rn "expire\|expir\|timeout\|invalid.*session\|session.*invalid" \
  --include="*.java" --include="*.kt" -i

# 외부 인증 서비스 호출 탐색
grep -rn "restTemplate\|WebClient\|axios\|fetch" \
  --include="*.java" --include="*.kt" --include="*.js" --include="*.ts" \
  | grep -i "session\|auth\|token"
```
