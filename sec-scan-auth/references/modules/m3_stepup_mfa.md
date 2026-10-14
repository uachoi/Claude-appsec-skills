## Module M3 — stepup-mfa (PIN·비밀번호 서버측 재검증 · 2차 인증/문자 인증 코드 신호)

**실행 조건**: `auth_map.module_plan.M3.run == true`
**Auto-Scan 연결**: `scan_pin_reverification`(`--skip pin`) — C-1 후보만 생성 (`result: "정보"`, `needs_review: true`). 결제류 컨트롤러 파일 단위로 확인 필드 참조 부재, 결제류 Request DTO의 pin/password 필드 부재를 탐지한다. 파일 단위 탐지라 공통 AOP/Service에서 검사하는 경우 오탐이 나므로 RULE-1과 같은 방식으로 호출 경로를 Read로 확인한 뒤 TP/FP를 판정한다. C-2 (2차 인증·문자 인증)는 스캐너 연결이 없다.
**finding category**: `PIN_REVERIFICATION_MISSING` (C-1에서만 생성)
**ID 접두어(task26_llm.json)**: `AUTH-PIN-NNN`

> 근거 원본 (원문 보존본): `methodology/auth_methodology.md`
> - Part A 5-4 (PIN / Password Server-Side Verification)
> - Part B Step 5 (PIN/비밀번호 인증 서버 검증 점검)
> - Part C 익명화 사례 A-01 (PIN 인증 우회), A-02 (결제 비밀번호 하드코딩)
> - Part D 인증 체크리스트 "PIN 서버 검증" 행
> 판정이 애매하면 위 원문 절을 직접 읽고 판단한다.

> **범위 원칙 (사용자 결정 1-a)**:
> - **C-1 PIN·비밀번호 재검증**은 원본에 판정 기준이 있으므로 finding까지 생성한다.
> - **C-2 2차 인증·문자 인증**은 **코드 신호만 기록**한다. 이 모듈은 우회 가능 여부를 판정하지 않고, 테스트 절차도 작성하지 않는다.
>   판정과 동적 확인은 진단자가 결정한다. C-2에서는 finding을 만들지 않는다.
> - `payment_or_quota == true`인 흐름의 수량/횟수 제한·중복 처리는 M4(logic-race) 소관이다. 여기서는 M4로 넘길 엔드포인트 목록만 기록한다.

> **경계**: 하드코딩된 비밀번호/키 **값 자체**는 `sec-scan-data`의 `HARDCODED_SECRET` 소관이다 (M1 경계 규칙과 동일).
> 이 모듈은 "사용자가 입력한 값이 서버 검증에 쓰이는가"라는 **인증 흐름**만 본다. 값 원문은 `code_snippet`에 넣지 않는다 (RULE-3).

---

### C-1. PIN / 비밀번호 서버측 재검증 (Auth 5-4 / Step 5)

**대상**: 결제·구매·충전·환불·선물·계정정보 변경 등 실행 전에 PIN/비밀번호 확인이 요구되는 API

```bash
# 세션/UserInfo 객체의 PIN·비밀번호 확인 필드
grep -rn "pinConfirmationDate\|passwordConfirmationDate\|pinStatus\|pinVerified\|pinTime" src/ --include="*.java" --include="*.kt" -n

# 확인 필드를 실제로 검사하는 위치 (양호 패턴 기준점 확보)
grep -rn "pinConfirmationDate\|passwordConfirmationDate" src/ --include="*.java" --include="*.kt" -B 3 -A 10

# 결제/구매/주문 컨트롤러 중 확인 필드를 참조하지 않는 파일
grep -rn "class.*Pay.*Controller\|class.*Purchase.*Controller\|class.*Order.*Controller\|class.*Charge.*Controller\|class.*Gift.*Controller" src/ --include="*.java" --include="*.kt" -l \
  | xargs grep -L "pinConfirmationDate\|passwordConfirmationDate" 2>/dev/null

# 결제/구매 Request DTO에 PIN/비밀번호 필드가 있는지
grep -rn "class.*Request\|data class.*Request" src/ --include="*.java" --include="*.kt" \
  | grep -i "pay\|purchase\|order\|join\|charge\|gift" | awk -F: '{print $1}' | sort -u \
  | xargs grep -ln "pin\|password\|secret" 2>/dev/null
```

**판정 절차**:
1. 같은 서비스 안에서 PIN 확인 시각을 검사하는 **양호 기준 API**를 먼저 찾는다 (원본 사례 A-01: 다른 결제 API는 검증, 신규 API만 생략).
2. 양호 기준 API와 같은 등급의 민감 액션 API를 나열하고, 각각 서버에서 확인 필드를 검사하는지 Read로 확인한다. 공통 AOP/Interceptor/Service 메서드에서 검사하면 그 호출 경로까지 따라간다.
3. 아래 기준으로 판정한다.

| 코드 상태 | 판정 |
|---|---|
| 확인 필드를 현재 시각과 비교해 유효시간(예: 10초) 초과·null이면 throw | 양호 |
| 민감 액션 API에서 확인 필드 검사 없음 | **PIN_REVERIFICATION_MISSING, 취약, High** |
| Request DTO에 PIN/비밀번호 필드도 없고 서버 검사도 없음 (UI에서만 강제) | **PIN_REVERIFICATION_MISSING, 취약, High** — 원본 5-4 "UI-only enforcement" |
| 사용자 입력 PIN/비밀번호를 무시하고 고정값으로 하위 결제 API 호출 (원본 사례 A-02) | **PIN_REVERIFICATION_MISSING, 취약, High** — 입력 검증이 형식화됨. 고정값 자체는 `manual_review_note`에 "sec-scan-data HARDCODED_SECRET 영역" 메모 |
| 검사는 있으나 null을 통과시키거나 유효시간 비교 방향이 뒤집힘 | **PIN_REVERIFICATION_MISSING, 취약, High** |
| 검사는 있으나 유효시간이 과도하게 김 (분 단위 이상) | **PIN_REVERIFICATION_MISSING, 취약, Medium** — 사유와 설정값 위치를 `manual_review_note`에 기록 |

```kotlin
// 양호 — 서버측 PIN 확인 시각 재검증 (원본 5-4)
val pinTimeDiff = if (userInfo.pinConfirmationDate != null)
    (Math.abs(System.currentTimeMillis() - userInfo.pinConfirmationDate) / 1000).toInt()
else -1
if (pinTimeDiff == -1 || pinTimeDiff > 10) throw PinConfirmationException()

// 취약 — UI만 PIN을 강제하고 서버는 검사하지 않음
fun joinPurchase(@RequestBody req: PurchaseRequest, userInfo: UserInfo) {
    // pinConfirmationDate 검사 없음
    purchaseService.join(req, userInfo)
}
```

**[추가] 판정 보강**:
- **심각도 조정**: 기본 High (taxonomy). 금전 이동이 없는 정보변경(예: 알림 설정)이면 Medium으로 하향하고, 원본 사례 A-01처럼 결제·구매면 High를 유지한다. 조정 사유는 `manual_review_note`에 `severity 조정: High → Medium (사유: ...)` 형식으로 남긴다.
- **확인 필드의 출처**: `pinConfirmationDate`가 서버 세션/인증 서버 응답에서 오는지, 요청 바디·헤더 값으로 채워지는지 확인한다. 요청 값으로 채워지면 검사가 있어도 클라이언트가 조작할 수 있으므로 **취약, High**로 둔다.
- **verification_status**: 검사 누락·DTO 필드 부재·고정값 대체는 코드로 확정 가능 → `code-confirmed`. 검사가 외부 결제 모듈/인증 서버에 위임되어 이 repo에서 확인할 수 없으면 `needs-dynamic-verification` + `result: "정보"`, 위임 대상(클래스/호출 URL 설정 키)을 `evidence_trail[]`에 남긴다.
- **원본 보고서 표기**: `title`은 `[PIN 검증 미흡] <API 경로>` 형식 (원본 Part C 명명 예시). `recommendation`은 "컨트롤러/공통 AOP에서 `pinConfirmationDate` 유효시간(예: 10초) 서버 검증 추가".

---

### C-2. 2차 인증 · 문자 인증 — 코드 신호 기록 (판정 없음)

**대상**: `auth_map.signals.mfa_otp == true`인 흐름 (인증번호 발송/검증, OTP, 본인확인 등)

**목적**: 진단자가 동적 확인 대상을 고를 수 있도록 **코드에서 보이는 사실만** 정리한다.
우회 가능 여부를 결론 내리지 않고, 공격 절차나 테스트 페이로드를 쓰지 않는다.

```bash
# 발송·검증 엔드포인트와 서비스 위치
grep -rn "otp\|totp\|mfa\|2fa\|twoFactor\|certNo\|authNo\|verifyCode\|verificationCode\|smsAuth\|sendSms" src/ --include="*.java" --include="*.kt" -i -l
grep -rn "@PostMapping\|@GetMapping\|@PutMapping" src/ --include="*.java" --include="*.kt" -A 3 | grep -i "otp\|cert\|verify\|sms\|auth.*no"
```

각 흐름에 대해 아래 항목을 **관찰값 그대로** 기록한다. 판단이 필요한 항목은 `unknown`으로 두고 이유를 적는다.

| 신호 키 | 기록 내용 | 값 예시 |
|---|---|---|
| `endpoints` | 발송 / 검증 / 후속 민감 액션 엔드포인트 | `POST /cert/send`, `POST /cert/verify`, `POST /account/change` |
| `server_verify_location` | 서버에서 입력값을 비교하는 코드 위치 (파일:라인), 외부 위임이면 위임 대상 | `CertService.kt:88` / `external: auth-server (설정 키 cert.verify.url)` / `not_found` |
| `verified_state_storage` | 검증 완료 상태를 어디에 두는지 | `server_session` / `redis(key prefix)` / `db` / `request_value` / `unknown` |
| `binding` | 검증 결과가 무엇과 묶이는지 | `user_id` / `session` / `transaction_id` / `none_observed` |
| `expiry` | 인증번호·검증 상태의 만료 설정 위치와 값 | `TTL 180s (application.yml cert.ttl)` / `not_found` |
| `attempt_limit` | 검증 실패 횟수 제한 코드 위치 | `CertService.kt:102 (5회)` / `not_found` |
| `send_rate_limit` | 발송 횟수/간격 제한 코드 위치 | `not_found` |
| `single_use` | 검증 성공 후 상태를 삭제·소진하는지 | `delete after verify (L110)` / `not_found` |
| `downstream_check` | 후속 민감 액션이 검증 상태를 다시 확인하는지 | `AccountController.kt:45 checks cert state` / `not_found` |
| `why_not_static` | 정적으로 확정할 수 없는 이유 | "검증이 외부 인증 서버에서 수행됨", "TTL이 인프라 설정" |
| `related_findings` | 관련 finding ID | `AUTH-BYP-002` / `[]` |

**기록 규칙**:
- 출력 위치: `task26_llm.json`의 `auth_access_assessment.stepup_signals[]` (흐름 1건 = 객체 1개, 위 신호 키 사용).
- `summary_auth.md`에는 「2차 인증·문자 인증 코드 신호」 표로 흐름별 1행 요약을 넣는다. 열: 흐름 / 서버 검증 위치 / 상태 저장 / 결합 / 만료 / 시도 제한 / 후속 확인.
- `not_found`는 "이 repo에서 찾지 못함"이라는 뜻이다. 취약으로 해석해 쓰지 않는다.
- 인증번호·OTP 시드·발송 API 키 등 **값 원문은 기록 금지** (RULE-3). 위치와 설정 키 이름만 적는다.
- 이 절의 내용으로 finding을 만들지 않는다. 다른 모듈의 판정 기준에 해당하는 사실이 나오면 해당 모듈로 넘긴다:
  - 검증 엔드포인트 자체가 인증 강제 대상에서 빠져 있음 → M1 A-1/A-2
  - 인증번호/검증 상태 조회가 요청 파라미터의 사용자 ID로 이뤄짐 → M2 A-5 (IDOR)
  - 검증과 후속 처리 사이의 동시 요청 문제 → M4
- 흐름마다 `dast_candidates_AUTH.json`에 후보 1건을 함께 기록한다 (`source_module: "M3"`, `kind: "stepup_mfa_flow"`, 형식은 `references/dast_candidates.md`). 신호 키는 `code_signals`에, `why_not_static`은 그대로 옮긴다.

---

### C-3. M4 이관 목록

`payment_or_quota == true`인 엔드포인트 중 수량·횟수·잔액 제한이 있는 것을 나열해 `auth_access_assessment.m4_handoff[]`에 `{endpoint, file, line, limit_kind}`로 기록한다 (원본 사례 A-03 "구매 제한 우회"는 M4에서 판정).

---

### M3 판정 요약표 (summary_auth.md 「모듈별 판정 요약」에 채움 — 원본 Final Verdict Summary Table 매핑)

| 점검 항목 | 양호 기준 | 취약 기준 |
|---|---|---|
| PIN 서버 검증 | pinConfirmationDate 타임스탬프를 서버에서 재검증 | 서버 검증 없음; Request DTO에 PIN 필드 없음 → UI 레벨만 강제 |
| PIN 입력값 사용 | 사용자 입력값이 서버 검증·하위 결제 호출에 사용됨 | 입력값 무시, 고정값으로 대체 |
| PIN 확인 필드 출처 | 서버 세션/인증 서버 응답 | 요청 바디·헤더 값 |
| 2차 인증·문자 인증 | — (판정 없음) | — 「2차 인증·문자 인증 코드 신호」 표 참조, 진단자 판단 |
