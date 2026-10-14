## Module M5 — webview-client (Native App ↔ Webview 세션 전달 · 앱 토큰 저장 · JS Bridge · 쿠키 공유)

**실행 조건**: `auth_map.module_plan.M5.run == true`
- `repo_type == "mobile-client"` → **M5만 실행** (M0 규칙). 서버 측 판정(인증 강제·IDOR·Race)은 하지 않는다.
- `backend` repo에서 M1 A-6이 Native App + Webview 구조를 확인한 경우 → E-0(서버 측)만 실행하고, 앱 코드가 없으므로 E-1~E-5는 "해당없음(앱 코드 미포함 repo)"으로 기록한다.
- `mixed` → 전 항목 실행.

**Auto-Scan 연결**: 없음 (`scan_auth_access_control.py`는 서버 코드 대상). LLM 수동 분석.
**finding category**: `SESSION_TOKEN_EXPOSURE` (주), 서버 측 사실은 M1/M2 category로 넘김
**ID 접두어(task26_llm.json)**: `AUTH-SESS-NNN`
**scope.type**: `file` (taxonomy 기본값)

> 근거 원본 (원문 보존본): `methodology/webview_session_methodology.md`
> - 2.1 / 2.3 (기술 스택·초기 탐색 — M0에서 수행), 3.1~3.3 (서버 측 흐름 추적·세션 검증 방식 분류)
> - 4.1~4.6 (Native ↔ Webview 전달 메커니즘, 저장 위치, 방식 1~5, 시나리오 A/B)
> - 5.1~5.6 (항목별 체크리스트), 6.1~6.3 (기록 템플릿), 7 (기술 스택별 탐색 포인트)
> 판정이 애매하면 위 원문 절을 직접 읽고 판단한다.

> **경계**:
> - 하드코딩된 테스트 계정/토큰 **값** → `sec-scan-data` `HARDCODED_SECRET`. 여기서는 위치만 `manual_review_note`에 메모.
> - 서버 로그에 세션 ID·개인정보 평문 기록 → `sec-scan-data` PII Logging. 여기서는 메모만.
> - Webview 페이지 자체의 XSS → `sec-scan-xss`. 여기서는 "XSS 발생 시 토큰 접근 가능 구조"라는 **구조 사실**만 판정한다.
> - CSRF 설정 → M2 B-1, 내부 API 경로 차단 → M1 A-6, 테스트 세션 우회 → M1 A-2 (원본 5.6의 해당 항목은 그 모듈에서 판정).

---

### E-0. 서버 측: 세션 검증 방식과 Webview 진입 흐름 (원본 3.1~3.3, 4.4, 5.5)

```bash
grep -rn "sessionId\|session_id\|accessToken\|access_token" src/ --include="*.java" --include="*.kt" --include="*.js" --include="*.ts"
grep -rn "x-.*session\|x-.*token" src/ . --include="*.java" --include="*.kt" --include="*.properties" --include="*.yml" -i
grep -rn "expire\|expir\|timeout\|invalid.*session\|session.*invalid" src/ --include="*.java" --include="*.kt" -i
grep -rn "restTemplate\|WebClient\|axios\|fetch" src/ --include="*.java" --include="*.kt" --include="*.js" --include="*.ts" | grep -i "session\|auth\|token"
grep -rn "refresh\|reissue\|refreshYn\|token/exchange" src/ --include="*.java" --include="*.kt" -i
```

- 탐색 순서는 원본 3.1을 따른다: ① Gateway/Filter → ② AOP/Annotation → ③ 세션 검증 서비스 → ④ DTO(UserInfo 등) → ⑤ Config/Properties. M0의 `auth_map`에 이미 기록된 파일은 다시 찾지 않는다.
- 세션 검증 방식 분류 (원본 3.3): 로컬(JWT) / 외부 서비스 호출 / DB 조회 / 캐시. 결과를 「인증 아키텍처 요약」(아래 E-6 템플릿 6.1)에 기록한다.
- **판정 대상이 아닌 기록 항목**: 검증 실패 응답 코드·에러 코드 체계, 검증 호출 빈도(매 요청/최초 1회/캐싱), 토큰 갱신·재발급 엔드포인트, 세션 타임아웃 설정값.
- **판정**: 서버가 Webview 전용 단기 토큰을 발급하는 Token Exchange 엔드포인트가 있으면 그 엔드포인트의 인증 강제 여부를 M1 A-2 기준으로, 요청 파라미터의 사용자 ID 사용 여부를 M2 A-5 기준으로 넘긴다.
- 세션/토큰 ID를 순차값·짧은 길이·예측 가능한 값(타임스탬프, 사용자 ID 조합)으로 생성하는 코드가 이 repo에 있으면 → **SESSION_TOKEN_EXPOSURE, 취약, High** (원본 5.6 "토큰/세션 ID 예측 가능성"). 생성이 외부 인증 서버에서 이뤄지면 `evidence_trail[]`에 "생성 주체 외부" 기록.
  ```bash
  grep -rn "UUID\|SecureRandom\|Random()\|currentTimeMillis\|nanoTime" src/ --include="*.java" --include="*.kt" -B 2 -A 2 | grep -i "session\|token"
  ```

### E-1. 앱 토큰 저장 위치 (원본 4.2, 5.1)

```bash
# Android
grep -rn "SharedPreferences\|EncryptedSharedPreferences\|Keystore\|DataStore" --include="*.java" --include="*.kt"
# iOS
grep -rn "UserDefaults\|SecItemAdd\|Keychain" --include="*.swift" --include="*.m"
# Flutter / React Native
grep -rn "flutter_secure_storage\|shared_preferences\|AsyncStorage\|SecureStore\|EncryptedStorage" --include="*.dart" --include="*.js" --include="*.ts"
```

| 저장소 | 판정 |
|---|---|
| EncryptedSharedPreferences / Keystore / Keychain / flutter_secure_storage / SecureStore | 양호 |
| 메모리(Singleton/전역 변수)만 | 양호 — 앱 재실행 후 세션 유지 방식만 기록 |
| SharedPreferences / UserDefaults / AsyncStorage / shared_preferences 에 세션·토큰 평문 저장 | **SESSION_TOKEN_EXPOSURE, 취약, Medium** |
| 외부 저장소(SD카드, 공용 디렉터리) | **SESSION_TOKEN_EXPOSURE, 취약, High** — 다른 앱 접근 가능 |

- 저장 키 이름이 세션/토큰/인증 정보인지 Read로 확인한다. 설정·플래그만 저장하면 대상이 아니다.
- **로그아웃 시 삭제**: 로그아웃 처리에서 해당 저장소 키를 지우는지 확인한다. 지우지 않으면 위 저장소 판정 finding의 `manual_review_note`에 함께 기록하고, 암호화 저장소인데 삭제만 없으면 → **SESSION_TOKEN_EXPOSURE, 취약, Low**.

### E-2. Native → Webview 전달 방식 식별 (원본 4.3 방식 1~5, 5.2)

```bash
grep -rn "loadUrl\|extraHeaders\|shouldInterceptRequest" --include="*.java" --include="*.kt"
grep -rn "loadUrl.*token\|loadUrl.*session\|loadUrl.*auth" --include="*.java" --include="*.kt" --include="*.swift"
grep -rn "addJavascriptInterface\|@JavascriptInterface\|WKScriptMessageHandler\|addScriptMessageHandler" --include="*.java" --include="*.kt" --include="*.swift"
grep -rn "CookieManager\|setCookie\|NSHTTPCookieStorage\|HTTPCookieStore\|WKHTTPCookieStore" --include="*.java" --include="*.kt" --include="*.swift"
grep -rn "evaluateJavascript\|evaluateScript\|postMessage" --include="*.java" --include="*.kt" --include="*.swift"
grep -rn "URLRequest\|setValue(.*forHTTPHeaderField" --include="*.swift"
```

전달 방식 번호(1~5, 복합 가능)와 전달 데이터 항목(세션 ID / 액세스 토큰 / 사용자 ID / CI / 기타)을 E-6 템플릿 6.2에 기록한 뒤, 방식별로 아래를 판정한다.

| 방식 | 판정 기준 |
|---|---|
| 1. extraHeaders | 헤더 주입 대상 URL이 고정 도메인 allowlist로 제한되면 양호. 임의 URL(딥링크·푸시·서버 응답으로 받은 URL)에도 같은 헤더를 붙이면 → **SESSION_TOKEN_EXPOSURE, 취약, High** (외부 도메인으로 토큰 전송). 최초 로드 이후 요청 처리 방식(`shouldInterceptRequest` / JS Bridge / 쿠키 병행)을 기록한다. `shouldInterceptRequest`가 모든 요청에 도메인 확인 없이 헤더를 붙이면 같은 기준으로 취약 |
| 2. URL 파라미터 | 토큰·세션 ID를 URL에 넣음 → **SESSION_TOKEN_EXPOSURE, 취약, Medium** (서버 로그·히스토리·Referer 노출). M1 A-6과 같은 건이면 한 건으로 병합 |
| 3. JS Bridge | 토큰을 반환하는 `@JavascriptInterface`/`WKScriptMessageHandler` 메서드가 있고, 로드 가능한 URL이 고정 도메인으로 제한되지 않음 → **SESSION_TOKEN_EXPOSURE, 취약, High**. 도메인 제한이 있으면 **Medium** (해당 도메인 XSS 시 토큰 접근 가능 구조). `minSdkVersion < 17`이면 원본 5.6 "Android 4.2 미만(CVE-2012-6636)"으로 `manual_review_note`에 기록하고 High 유지 |
| 4. 쿠키 공유 | `setCookie` 값에 `HttpOnly`/`Secure`가 없으면 → **SESSION_TOKEN_EXPOSURE, 취약, Medium**. `Domain`이 상위 도메인으로 넓게 잡혀 서브도메인 전체에 전송되면 같은 finding의 `manual_review_note`에 기록 |
| 5. evaluateJavascript / postMessage | 토큰을 `window` 전역 변수에 넣음 → **SESSION_TOKEN_EXPOSURE, 취약, Medium**. `postMessage(..., '*')`로 대상 origin 없이 전달 → **SESSION_TOKEN_EXPOSURE, 취약, High** |

**[추가] 판정 보강**:
- **로드 URL 제한**: 방식 1·3·5 판정의 핵심은 "어떤 URL에서 토큰을 받을 수 있는가"이다. `shouldOverrideUrlLoading`/`decidePolicyFor navigationAction`에서 도메인 allowlist를 **정확 일치 또는 정확한 suffix(`.example.com`) 비교**로 하는지 확인한다. `contains()`/`startsWith("https://example")` 같은 문자열 비교면 우회 가능한 제한으로 보고 "제한 없음"과 같이 판정한다 (M2 IP ACL `contains()` 판정과 같은 논리).
  ```bash
  grep -rn "shouldOverrideUrlLoading\|decidePolicyFor\|navigationAction\|getHost()\|\.host" --include="*.java" --include="*.kt" --include="*.swift" -A 8
  ```
- **세션 공유 범위** (원본 5.3): Native 세션과 Webview 세션이 같은지, Webview가 자체 로그인으로 별도 세션을 갖는지 기록한다. 별도 관리면 로그아웃 동기화(앱 로그아웃 시 `CookieManager.removeAllCookies`/`WKWebsiteDataStore` 삭제) 여부를 확인하고, 없으면 → **SESSION_TOKEN_EXPOSURE, 취약, Low**.
- **verification_status**: 앱 코드에서 위 구조가 명확하면 `code-confirmed`. 토큰 전달 대상 URL이 서버 응답·원격 설정으로 결정되어 코드에서 범위를 확정할 수 없으면 `needs-dynamic-verification` → DAST 후보 (`kind: "webview_session"`).

### E-3. 전송 채널 (원본 5.6 "토큰 전송 채널 보안")

```bash
grep -rn "cleartextTrafficPermitted\|usesCleartextTraffic\|network_security_config" --include="*.xml"
grep -rn "NSAllowsArbitraryLoads\|NSExceptionAllowsInsecureHTTPLoads" --include="*.plist"
grep -rn "http://" --include="*.java" --include="*.kt" --include="*.swift" --include="*.dart" --include="*.ts" --include="*.xml" --include="*.plist" | grep -v "schemas.android.com\|www.w3.org\|localhost\|127.0.0.1"
grep -rn "onReceivedSslError\|handler.proceed\|ServerTrust\|allowsInvalidSSL\|badCertificateCallback" --include="*.java" --include="*.kt" --include="*.swift" --include="*.dart" -A 3
grep -rn "CertificatePinner\|pin-set\|TrustKit\|pinnedCertificates" --include="*.java" --include="*.kt" --include="*.swift" --include="*.xml" --include="*.dart"
```

| 코드 상태 | 판정 |
|---|---|
| 앱 전역 cleartext 허용 또는 iOS ATS 전역 해제, 토큰 전달 URL에 `http://` 포함 | **SESSION_TOKEN_EXPOSURE, 취약, High** |
| 전역 cleartext 허용이지만 토큰 전달 URL은 모두 https | **SESSION_TOKEN_EXPOSURE, 취약, Medium** |
| `onReceivedSslError`에서 `handler.proceed()` 무조건 호출, 인증서 검증 무력화 콜백 | **SESSION_TOKEN_EXPOSURE, 취약, High** |
| 인증서 피닝 없음 | finding 없음. 「인증 아키텍처 요약」에 "피닝 미적용" 기록 (원본은 확인 항목으로만 제시) |

- cleartext 예외가 특정 개발 도메인으로만 한정되고 빌드 타입(debug)으로 분리되어 있으면 양호, 분리 여부를 확정할 수 없으면 Medium + `needs-dynamic-verification`.
- M1 A-6 "Native App→Webview 헤더 주입 구조에서 TLS 미적용 구간"과 같은 건이면 한 건으로 병합한다 (서버·앱 증거를 `evidence_trail[]`에 함께).

### E-4. 시나리오 흐름 기록 (원본 4.5 / 4.6)

finding을 만들지 않고, 아래 흐름을 코드 위치와 함께 「인증 아키텍처 요약」에 서술한다. 판정이 필요한 사실이 나오면 E-1~E-3 또는 M1/M2로 넘긴다.

- **시나리오 A (비로그인 → 로그인 → Webview)**: 로그인 응답에서 토큰 발급 위치(바디 필드명 / 응답 헤더 이름) → 앱 저장 위치(E-1) → 전달 방식(E-2) → Webview 첫 API의 서버 검증 흐름(E-0) → 인증 레벨(role/scope 등 코드값) 요구 여부.
- **시나리오 B (로그인 상태 → Webview)**: 진입 전 만료 확인 여부 → 만료 시 서버 응답 코드와 앱 처리(재로그인/자동 갱신) → 갱신 파라미터·엔드포인트 → 세션 타임아웃 설정값.
- 필드명·헤더 이름만 기록하고 **값은 기록하지 않는다** (RULE-3).

### E-5. 앱 측 테스트/개발 우회 잔존 (원본 5.6)

```bash
grep -rn "BuildConfig.DEBUG\|isDebug\|kDebugMode\|__DEV__" --include="*.java" --include="*.kt" --include="*.swift" --include="*.dart" --include="*.js" --include="*.ts" -A 5 | grep -i "session\|token\|auth\|login\|url"
grep -rn "setWebContentsDebuggingEnabled" --include="*.java" --include="*.kt" -B 2 -A 2
```

- 디버그 분기 없이 고정 토큰·테스트 계정으로 로그인하거나 인증을 건너뛰는 앱 코드 → **SESSION_TOKEN_EXPOSURE, 취약, High**, 값 자체는 `sec-scan-data` 메모.
- `setWebContentsDebuggingEnabled(true)`가 debug 빌드 분기 없이 호출됨 → **SESSION_TOKEN_EXPOSURE, 취약, Medium** (운영 앱에서 Webview 원격 디버깅으로 세션 접근 가능 구조).

### E-6. summary_auth.md 「인증 아키텍처 요약」 기록 템플릿 (원본 6.1 / 6.2 그대로)

**6.1 인증 방식 요약**

| 항목 | 발견값 | 비고 |
|------|--------|------|
| 세션 토큰 헤더 키 이름 | | |
| 세션 검증 방식 | 로컬 / 외부서비스 / DB / 캐시 | |
| 쿠키 사용 여부 | 사용 / 미사용 | |
| JWT 사용 여부 | 사용 / 미사용 | |
| 토큰 갱신(refresh) 여부 | 있음 / 없음 | |
| 인증 레벨 분류 체계 | | 코드값 목록 |
| 세션 검증 외부 서비스 URL | | 설정 키 이름만 (값은 RULE-3 마스킹) |

**6.2 Native → Webview 전달 방식**

| 항목 | 발견값 |
|------|--------|
| 전달 방식 (4.3 기준 방식 번호) | |
| 앱 토큰 저장 위치 (4.2 기준) | |
| 전달되는 데이터 항목 | |
| 최초 로드 이후 요청 처리 방식 | |

- 원본 6.3(보안 취약점 발견 목록)은 별도 표로 만들지 않는다. `task26_llm.json` findings와 summary의 「모듈별 판정 요약」이 대신한다. 위험도는 원본 상/중/하 대신 severity(High/Medium/Low)를 쓴다.
- M1 A-6의 아키텍처 유형 분류 표와 같은 절에 둔다. `backend` repo에서 E-0만 실행한 경우 6.2는 "앱 코드 미포함 — 서버 측 신호만" 으로 적는다.

---

### M5 판정 요약표 (summary_auth.md 「모듈별 판정 요약」에 채움 — 원본 5.1~5.6 체크리스트 매핑)

| 점검 항목 | 양호 기준 | 취약 기준 |
|---|---|---|
| 앱 토큰 저장 | Keychain / EncryptedSharedPreferences / SecureStorage | SharedPreferences·UserDefaults 평문, 외부 저장소 |
| 로그아웃 시 토큰 삭제 | 저장소·Webview 쿠키 삭제 | 삭제 없음 |
| 전달 방식 1 (extraHeaders) | 고정 도메인 allowlist에만 헤더 주입 | 임의 URL에 헤더 주입 |
| 전달 방식 2 (URL 파라미터) | 사용 안 함 | 토큰이 URL에 포함 |
| 전달 방식 3 (JS Bridge) | 토큰 반환 메서드 없음 또는 정확한 도메인 제한 | 도메인 제한 없이 토큰 반환 |
| 전달 방식 4 (쿠키) | HttpOnly·Secure·좁은 Domain | 플래그 누락 |
| 전달 방식 5 (evaluateJavascript) | 전역 변수·와일드카드 postMessage 미사용 | `window` 전역 토큰, `postMessage(..., '*')` |
| 로드 URL 제한 | 정확 일치/정확한 suffix 비교 | `contains()`/prefix 문자열 비교 또는 제한 없음 |
| 전송 채널 | HTTPS 강제, 인증서 검증 유지 | cleartext 허용, SSL 오류 무시 |
| 세션 ID 생성 | SecureRandom/UUID 등 예측 불가 | 순차·타임스탬프·짧은 길이 |
| 앱 디버그 우회 | debug 빌드 분기 | 운영 빌드에 고정 토큰·인증 생략·원격 디버깅 |
| 인증서 피닝 | — (기록만) | — |
