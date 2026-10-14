# Race Condition / TOCTOU 진단 방법론 (STEP 1~7, P1~P9)

> **이 파일의 위치와 우선순위**
> - 이 파일은 원본 진단 방법론을 **원문 그대로 보존**한 참조 자료다 (라인 단위 복사, 고객사 식별정보만 익명화).
> - 실행 절차·판정 심각도·출력 형식은 `references/task_prompts/task_26_auth_review.md`가 **우선**한다.
> - 원본의 "Output language", "Final Verdict Summary Table", "Finding Report Format" 지시는
>   task_26 「원본 방법론 출력 지시 매핑」 규칙에 따라 `task26_llm.json` / `summary_auth.md` / `dast_candidates_AUTH.json`으로 매핑된다.
> - 원본 사례(파일명·클래스명·IP·헤더명)는 익명화 예시다. 실제 진단 대상의 이름으로 간주하지 말 것.

> task_26 연결: Section C (C-1 ~ C-8), Section E (DAST 후보)

## Part A — Race Condition 분석 방법론 (RACE_CONDITION_ANALYSIS)

> 📎 원본: `MySkills/6. RACE_CONDITION_ANALYSIS.md` L1-7 (원문 보존, 익명화 적용)

### Race Condition (동시성 제어 미흡) 취약점 분석 방법론

> 작성일: 2026-03-30
> 적용 대상: Spring Boot + Kotlin/Java 기반 서비스 (서비스 종속 내용 없음)
> 목적: 임의의 서비스 소스코드에서 Race Condition 취약 지점을 체계적으로 탐지

---


> 📎 원본: `MySkills/6. RACE_CONDITION_ANALYSIS.md` L18-575 (원문 보존, 익명화 적용)

---

### 1. 분석 방법론 개요

#### 핵심 원칙

Race Condition(경쟁 조건)은 **검증(READ)**과 **실행(WRITE)**이 원자적으로 처리되지 않을 때,
두 요청이 동시에 "검증 통과" 상태를 보고 중복 실행되는 취약점이다.

```
[Thread A]  SELECT → (검증 통과) --------→ INSERT/UPDATE
[Thread B]  SELECT →          (검증 통과) → INSERT/UPDATE  ← 중복 실행!
                 ↑
         이 구간이 잠금 없이 열려 있으면 취약
```

**OWASP 분류**: ASVS V11 (Business Logic), CWE-362 (Race Condition), CWE-367 (TOCTOU)

#### 분석 대상 레이어

```
[컨트롤러] → @Transactional 범위 시작 여부
[서비스]   → 검증 로직(SELECT-then-Act) 위치, @Transactional 범위
[레포지토리] → SELECT FOR UPDATE 사용 여부, UNIQUE CONSTRAINT 존재 여부
[DB]       → 트랜잭션 격리 수준, 행 수준 잠금(Row Lock)
```

---

### 2. Step-by-Step 탐지 절차

#### STEP 1 — 금전/포인트/수량 관련 핵심 API 식별

비즈니스 로직 상 중복 실행 시 피해가 발생하는 API를 먼저 식별한다.

```bash
# 결제/구매/취소/환불 관련 컨트롤러 엔드포인트 탐지
grep -rn "@PostMapping\|@PutMapping\|@DeleteMapping" src/ \
  --include="*.kt" --include="*.java" | \
  grep -i "purchase\|buy\|cancel\|refund\|issue\|point\|coupon\|payment\|order\|charge"

# GET이지만 상태를 변경하는 잘못된 설계 탐지
grep -rn "@GetMapping" src/ \
  --include="*.kt" --include="*.java" | \
  grep -i "apply\|register\|confirm\|execute\|process"
```

**판단**: 식별된 엔드포인트별로 STEP 2~6을 순서대로 적용한다.

---

#### STEP 2 — @Transactional 범위 분석

##### 2-1. 서비스 메서드에 @Transactional이 없는 위치 탐지

```bash
# @Transactional 없이 저장/수정/삭제를 직접 호출하는 서비스 메서드 탐지
# (패턴: fun 으로 시작하는 메서드 위에 @Transactional 없음)
grep -rn "fun " src/ --include="*.kt" -A 5 | grep -v "@Transactional" | \
  grep "repository\.save\|repository\.delete\|repository\.update\|\.save(\|\.delete("

# Java의 경우
grep -rn "public\|private\|protected" src/ --include="*.java" -B 3 | \
  grep -v "@Transactional" | grep "repository\.save\|repository\.delete"
```

**더 정확한 방법** — 파일을 직접 열어 다음 패턴을 순서대로 확인:

1. 클래스/메서드 레벨에 `@Transactional` 있는지 확인
2. `@Transactional`이 없는 메서드에서 `repository.save()`, `repository.delete()`, `jdbcTemplate.update()` 등을 호출하는지 확인
3. 해당 메서드 내에 **검증 로직(SELECT) + 실행 로직(INSERT/UPDATE)**이 함께 있는지 확인

##### 2-2. @Transactional propagation 분석

```bash
# REQUIRES_NEW로 분리된 내부 트랜잭션 탐지
grep -rn "Propagation.REQUIRES_NEW\|propagation = Propagation" src/ \
  --include="*.kt" --include="*.java"
```

**위험 패턴**: 외부 메서드에 `@Transactional`이 없고, 내부 메서드만 `REQUIRES_NEW`인 경우

| 외부 @Transactional | 내부 propagation | 판정 |
|---|---|---|
| 없음 | REQUIRES_NEW | **취약** — 외부에서 원자성 보장 안 됨 |
| 있음 | REQUIRES_NEW | 내부는 독립 트랜잭션, 외부 롤백이 내부에 영향 안 줌 → 설계 의도 확인 필요 |
| 있음 | REQUIRED (기본값) | 안전 — 같은 트랜잭션 공유 |
| 없음 | 없음 | **취약** — 완전한 비트랜잭션 환경 |

---

#### STEP 3 — SELECT-then-Act 패턴 탐지

검증(SELECT)과 실행(WRITE)이 **하나의 원자적 트랜잭션**으로 묶여있지 않으면 취약하다.

```bash
# 존재 여부 체크 메서드 탐지 (이런 메서드 이름은 SELECT-then-Act 패턴 신호)
grep -rn "fun has\|fun exists\|fun check\|fun validate\|fun verify\|fun isValid\|fun isDuplicate" \
  src/ --include="*.kt" --include="*.java"

# count/exists 기반 중복 체크 탐지
grep -rn "\.count()\|\.exists()\|countBy\|existsBy\|SELECT COUNT" \
  src/ --include="*.kt" --include="*.java" --include="*.xml"
```

**탐지 후 확인 절차**:

1. 체크 메서드가 호출되는 서비스 메서드를 찾는다
2. 그 서비스 메서드에 `@Transactional`이 있는지 확인한다
3. `@Transactional`이 있더라도 SELECT에 `FOR UPDATE`가 없으면 **동시 읽기 허용** 상태 — 여전히 취약

```bash
# SELECT 후 save/insert 호출 패턴 (같은 메서드 내에 있는지 파일 단위 확인)
grep -rn "findBy\|findAll\|selectBy" src/ --include="*.kt" --include="*.java" -A 10 | \
  grep "\.save(\|\.insert\|\.update\|repository\."
```

---

#### STEP 4 — SELECT FOR UPDATE (비관적 락) 사용 여부 탐지

```bash
# JPA @Lock 어노테이션 탐지
grep -rn "@Lock\|LockModeType\|PESSIMISTIC_WRITE\|PESSIMISTIC_READ" \
  src/ --include="*.kt" --include="*.java"

# MyBatis/JdbcTemplate 직접 쿼리에서 FOR UPDATE 탐지
grep -rn "FOR UPDATE\|for update\|NOWAIT\|SKIP LOCKED" \
  src/ --include="*.kt" --include="*.java" --include="*.xml" --include="*.sql"

# Spring Data JPA 커스텀 쿼리에서 탐지
grep -rn "@Query" src/ --include="*.kt" --include="*.java" -A 3 | \
  grep -i "for update\|pessimistic"
```

**판단 기준**:

| 상황 | FOR UPDATE 필요 여부 |
|---|---|
| 동시 요청이 같은 행을 검증 후 수정 | **필요** |
| 배치 처리에서 여러 행을 순차 처리 | 행 단위 FOR UPDATE 또는 분산 락 필요 |
| 단순 조회 후 다른 테이블에 INSERT | 조회 테이블에 FOR UPDATE 필요 |
| UNIQUE CONSTRAINT로 DB가 중복을 막음 | FOR UPDATE 없이도 가능 (단, 예외 처리 필요) |

---

#### STEP 5 — 예외 묵살(Silent Exception Swallowing) 패턴 탐지

Race Condition 발생 시 예외가 묵살되면 오동작이 감지되지 않는다.

```bash
# catch 블록에서 아무것도 안 하거나 로그만 찍는 패턴 탐지
grep -rn "catch" src/ --include="*.kt" --include="*.java" -A 3 | \
  grep -v "throw\|rethrow\|log\.\|logger\." | grep "}"

# catch 후 finally에서 동일 로직을 다시 실행하는 이중 실행 패턴
grep -rn "} catch\|} finally" src/ --include="*.kt" --include="*.java" -B 2 -A 5
```

**위험 패턴 예시**:
```kotlin
try {
    externalApiCall()   // 외부 API 호출
} catch (e: Exception) {
    log.error("failed")  // ← 예외 삼킴! 실패해도 이후 로직 계속 실행
}
doNextStep()  // ← externalApiCall 실패했어도 여기까지 도달
```

**취약 판정 조건**: `catch` 블록에서 `throw`/`return`/`rethrow` 없이 이후 코드가 계속 실행되는 경우

---

#### STEP 6 — 배치/정산 API의 동시성 제어 탐지

배치 API는 단건 API보다 처리량이 많아 Race Condition 발생 시 피해가 크다.

```bash
# 배치/정산/스케줄 관련 컨트롤러 탐지
grep -rn "@Scheduled\|@PostMapping\|@GetMapping" src/ \
  --include="*.kt" --include="*.java" | \
  grep -i "batch\|settlement\|schedule\|process\|execute\|job"

# 배치 메서드에서 @Transactional 없이 반복 처리하는 패턴
grep -rn "forEach\|for (\|\.map {" src/ --include="*.kt" --include="*.java" -B 5 | \
  grep -v "@Transactional" | grep "repository\.\|service\."
```

**배치에서 확인할 추가 항목**:

1. **중복 실행 방지**: 같은 배치 작업이 동시에 두 번 실행될 수 있는지 (분산 락/DB 락 여부)
2. **처리 상태 관리**: 처리 중인 항목에 상태 플래그 업데이트가 SELECT 전에 이루어지는지
3. **Redis/Cache 기반 중복 방지**: Redis putHash/get이 실제 가드로 사용되는지, 아니면 기록용인지

```bash
# Redis 사용 위치 탐지
grep -rn "redisService\.\|redisTemplate\.\|RedisTemplate" \
  src/ --include="*.kt" --include="*.java" | \
  grep -i "put\|set\|get\|exists\|lock"
```

---

#### STEP 7 — DB 수준 안전장치 확인

```bash
# Entity/Domain 클래스에서 UNIQUE 제약 탐지
grep -rn "@UniqueConstraint\|@Column(unique\|UNIQUE INDEX\|unique = true" \
  src/ --include="*.kt" --include="*.java" --include="*.xml"

# 낙관적 락(@Version) 사용 여부 탐지
grep -rn "@Version" src/ --include="*.kt" --include="*.java"
```

| 안전장치 | 효과 | 한계 |
|---|---|---|
| DB UNIQUE CONSTRAINT | 중복 INSERT를 DB가 차단 | 예외 처리 코드 필요, UPDATE 중복엔 미적용 |
| @Version (낙관적 락) | 동시 수정 감지 후 예외 발생 | 재시도 로직 필요, 충돌 빈도 높으면 성능 저하 |
| SELECT FOR UPDATE (비관적 락) | 행 단위 잠금으로 동시 접근 차단 | 데드락 위험, 성능 저하 가능 |
| 분산 락 (Redis/Zookeeper) | 서버가 여러 대여도 단일 진입 보장 | 인프라 의존성, 락 해제 실패 시 교착 |

---

### 3. 취약 패턴 판단 기준표

| # | 탐지 패턴 | 취약 판정 조건 | 위험도 |
|---|---|---|---|
| P1 | @Transactional 없는 검증+실행 | 동일 메서드에 SELECT + INSERT/UPDATE가 @Transactional 없이 존재 | **높음** |
| P2 | @Transactional 있지만 FOR UPDATE 없음 | READ COMMITTED 격리 수준에서 SELECT 동시 읽기 허용 | **중간~높음** |
| P3 | REQUIRES_NEW 분리 + 외부 @Transactional 없음 | 배치 청크 처리 시 중복 실행 가능 | **높음** |
| P4 | SELECT COUNT/EXISTS 후 INSERT | 원자적 처리 보장 없음, UNIQUE CONSTRAINT도 없음 | **높음** |
| P5 | 예외 묵살 후 후속 로직 실행 | catch 블록에 throw/return 없음 | **중간** |
| P6 | Redis 기록만 있고 가드(get+check) 없음 | 중복 방지 효과 없음 | **중간** |
| P7 | 배치 @Transactional 없는 forEach/map | 건당 원자성 보장 없음 | **높음** |
| P8 | 외부 API 연동 취소/환불에서 보상 트랜잭션 미구현 | @Transactional 없는 메서드에서 외부 API + DB 저장 혼재, 또는 catch-finally 이중 호출 | **높음** |
| P9 | 배치 최상위 @Transactional 없음 + REQUIRES_NEW 단독 + 분산 락 없음 | 배치 API 동시 호출 시 같은 항목 중복 처리, 처리 전 상태 변경(LOCK) 없음 | **높음** |

---

### 4. 수정 위치 결정 트리

```
[취약 메서드 발견]
        │
        ▼
  @Transactional이 없는가?
    │                  │
   Yes                 No
    │                  │
    ▼                  ▼
 @Transactional     SELECT에 FOR UPDATE가 없는가?
 추가 검토              │                  │
                       Yes                 No
                        │                  │
                        ▼                  ▼
                  SELECT FOR UPDATE    UNIQUE CONSTRAINT가 없는가?
                  추가 검토              │                  │
                                        Yes                 No
                                         │                  │
                                         ▼                  ▼
                                    DB UNIQUE           예외 처리
                                    CONSTRAINT          추가 검토
                                    추가 검토
```

#### 각 수정 방법의 적용 위치

| 수정 방법 | 적용 위치 | 효과 | 주의사항 |
|---|---|---|---|
| `@Transactional` 추가 | 서비스 메서드 | SELECT+INSERT 원자성 확보 | 단독으로는 동시 읽기 차단 안 됨 |
| `SELECT FOR UPDATE` 추가 | Repository 쿼리 | 행 단위 잠금, 동시 읽기 차단 | @Transactional과 함께 사용 필수 |
| DB UNIQUE CONSTRAINT | Entity/DDL | DB 레벨 중복 차단 | 예외(DataIntegrityViolationException) 처리 필요 |
| `@Version` (낙관적 락) | Entity 필드 | 동시 수정 시 OptimisticLockingFailureException | 재시도 정책 설계 필요 |
| 분산 락 (Redis) | 서비스 메서드 시작 | 서버 다중화 환경에서도 단일 진입 | 락 TTL, 해제 실패 처리 설계 필요 |
| 예외 rethrow 추가 | catch 블록 | 실패 시 후속 로직 차단 | 호출자에서 예외 처리 필요 |

---

### 5. 취약점 보고서 작성 가이드

#### 항목명 명명 규칙

```
[OWASP 분류] - [취약 기능명] - [취약 원인]

예시:
- 비즈니스 로직 우회 - 포인트 취소 - 동시성 제어 미흡 (Race Condition)
- 비즈니스 로직 우회 - 정산 배치 - 트랜잭션 원자성 미보장
- 비즈니스 로직 우회 - 쿠폰 발급 - TOCTOU(Time-of-Check to Time-of-Use)
```

#### 보고서 항목 구성

```
■ 취약점 항목명
  예) 비즈니스 로직 우회 - [기능명] - 동시성 제어 미흡

■ 위험도
  상/중/하 + 근거 (중복 요청 수행 용이성, 피해 규모)

■ 취약 발생 위치
  파일 경로 + 라인 번호
  예) src/.../XxxService.kt:123 — cancelXxx() 메서드

■ 취약 코드 발췌
  문제가 되는 코드 블록 (5~15줄 이내)

■ 취약 근거
  1. 어느 위치에 @Transactional이 없는지
  2. SELECT 쿼리가 FOR UPDATE 없이 실행되는 이유
  3. 동시 요청 시 어떤 순서로 Race Condition이 발생하는지 (시나리오)

■ 재현 시나리오 (개념)
  Thread A: [동작 순서]
  Thread B: [동작 순서]
  결과: [부정 이득 또는 데이터 불일치]

■ 보안 대책
  단기: @Transactional + SELECT FOR UPDATE 추가
  장기: DB UNIQUE CONSTRAINT, 분산 락, 낙관적 락 검토
  코드 예시 포함
```

---

### 6. 체크리스트

#### Phase 1 — 대상 API 식별

- [ ] 금전/포인트/수량 변경 POST/PUT/DELETE API 목록 작성
- [ ] 상태를 변경하는 GET API(잘못된 설계) 식별

#### Phase 2 — @Transactional 분석

- [ ] 핵심 서비스 메서드에 `@Transactional` 있는지 확인
- [ ] `propagation = REQUIRES_NEW` 사용 위치에서 외부 메서드 @Transactional 확인
- [ ] 클래스 레벨 `@Transactional`이 메서드 레벨에서 override되는지 확인

#### Phase 3 — SELECT-then-Act 패턴

- [ ] 검증 메서드(`has*`, `exists*`, `check*`, `count*`) 위치 식별
- [ ] 검증 메서드 호출부에서 실행 메서드(`save*`, `insert*`, `issue*`)까지 하나의 @Transactional 범위 안에 있는지 확인
- [ ] SELECT 쿼리에 `FOR UPDATE` 또는 `@Lock(PESSIMISTIC_WRITE)` 있는지 확인

#### Phase 4 — 예외 처리

- [ ] catch 블록에 `throw`/`return` 없이 계속 실행되는 패턴 있는지 확인
- [ ] try-catch-finally에서 동일 로직 이중 실행 여부 확인

#### Phase 5 — DB 안전장치

- [ ] 중복 방지가 필요한 Entity에 UNIQUE CONSTRAINT 있는지 확인
- [ ] `@Version` 또는 `@Lock` 사용 여부 확인
- [ ] Redis 기반 중복 방지가 실제 가드 역할을 하는지 (get→check→set 순서) 확인

#### Phase 6 — 배치/정산 전용

- [ ] 배치 메서드 최상위 레벨에 `@Transactional` 있는지 확인
- [ ] 배치 API에 인증(`@Session`, `@Acl`) 또는 분산 락이 있는지 확인
- [ ] 배치 재실행 시 이미 처리된 항목을 건너뛰는 상태 체크 로직 있는지 확인

---

### 부록 — 자주 등장하는 취약 코드 패턴 vs 안전 코드 패턴

#### 패턴 A: @Transactional 없는 검증+실행

```kotlin
// ❌ 취약: @Transactional 없음
fun issueCoupon(userId: String, couponCode: String) {
    if (hasPurchaseHistory(userId, couponCode)) throw Exception("이미 구매")  // SELECT
    val coupon = couponRepository.save(...)                                    // INSERT
}

// ✅ 안전: @Transactional + SELECT FOR UPDATE
@Transactional
fun issueCoupon(userId: String, couponCode: String) {
    val coupon = couponRepository.findByCouponCodeForUpdate(couponCode)       // SELECT FOR UPDATE
    if (coupon.isAlreadyIssued(userId)) throw Exception("이미 구매")
    couponRepository.save(...)
}
```

#### 패턴 B: REQUIRES_NEW 단독 사용

```kotlin
// ❌ 취약: 외부는 @Transactional 없음
fun processAll(items: List<Item>) {       // @Transactional 없음!
    items.forEach { processOne(it) }
}

@Transactional(propagation = REQUIRES_NEW)
fun processOne(item: Item) { ... }        // 각 건이 독립 트랜잭션이지만 중복 호출 방지 안 됨

// ✅ 안전: 비관적 락 또는 상태 먼저 변경
@Transactional(propagation = REQUIRES_NEW)
fun processOne(item: Item) {
    val locked = itemRepository.findByIdForUpdate(item.id)   // SELECT FOR UPDATE
    if (locked.status == ALREADY_PROCESSED) return            // 중복 처리 방지
    locked.status = PROCESSING
    itemRepository.save(locked)
    // ... 이후 처리
}
```

#### 패턴 C: 예외 묵살

```kotlin
// ❌ 취약: 예외 묵살 후 후속 로직 실행
try {
    externalApiCall()
} catch (e: Exception) {
    log.error("API 실패: ${e.message}")   // throw 없음 → 이후 코드 실행됨
}
recordSuccess()  // ← API 실패했어도 실행됨!

// ✅ 안전: 예외 rethrow 또는 상태 확인
try {
    externalApiCall()
} catch (e: Exception) {
    log.error("API 실패: ${e.message}")
    throw ServiceRuntimeException("EXTERNAL_API_FAILED")  // rethrow
}
```

#### 패턴 D: 외부 API 연동 취소/환불에서 보상 트랜잭션 미구현 (P8)

외부 API(결제, 포인트, 쿠폰 등) 호출이 포함된 취소/환불 흐름에서 발생하는 패턴이다.
DB 트랜잭션은 롤백 가능하지만 외부 API 호출은 롤백 불가능하다는 점을 이용한다.

**탐지 방법**:
```bash
# @Transactional 없는 취소/환불 메서드에서 외부 API + DB 저장이 함께 있는지 확인
grep -rn "fun cancel\|fun refund\|fun rollback\|fun revert" \
  src/ --include="*.kt" --include="*.java" -A 30 | \
  grep -B 5 "restTemplate\|WebClient\|feignClient\|\.call(\|\.send("
```

**위험 패턴 1 — @Transactional 없는 외부 API + DB 혼합**:
```kotlin
// ❌ 취약: @Transactional 없음
fun cancelOrder(userId: String, orderId: String) {
    externalPaymentApi.cancel(orderId)    // 외부 API 호출 (롤백 불가)
    orderRepository.delete(orderId)       // DB 저장 (롤백 가능)
    // DB 실패 시 외부 API는 이미 취소됐지만 DB는 취소 안 됨 → 데이터 불일치
}
```

**위험 패턴 2 — catch + finally 이중 호출**:
```kotlin
// ❌ 취약: 정상 실행 시 externalApiCall()이 try + finally = 2회 호출됨
try {
    externalApiCall()     // 1회 호출
} catch (e: Exception) {
    log.error("실패: ${e.message}")   // 예외 묵살
} finally {
    externalApiCall()     // 항상 실행 → 정상 시 2회, 예외 시 1회
}
```

**추가 grep — catch-finally 이중 호출 패턴**:
```bash
grep -rn "} catch\|} finally" src/ --include="*.kt" --include="*.java" -B 2 -A 8 | \
  grep -B 5 "externalApi\|restTemplate\|\.call(\|paymentApi\|pointApi"
```

**안전한 구조**:
```kotlin
// ✅ 안전: 외부 API 실패 시 즉시 중단, 성공 후 DB 처리
@Transactional
fun cancelOrder(userId: String, orderId: String) {
    val result = externalPaymentApi.cancel(orderId)
    if (!result.isSuccess) throw RuntimeException("외부 API 취소 실패")
    orderRepository.updateStatus(orderId, CANCELLED)
    // 또는 외부 API 실패 시 보상 트랜잭션(재시도/수동 처리) 설계
}
```

**판단 기준**:

| 조건 | 판정 |
|---|---|
| @Transactional 없음 + 외부 API + DB 저장 혼재 | **취약** |
| catch 블록 예외 묵살 + finally에서 동일 외부 API 재호출 | **취약** (이중 호출) |
| 외부 API 실패 시 rethrow 없이 후속 DB 저장 실행 | **취약** |
| 외부 API 실패 → 즉시 예외 throw, DB 롤백 | 안전 |

---

#### 패턴 E: 배치 최상위 @Transactional 없음 + REQUIRES_NEW 단독 + 분산 락 없음 (P9)

배치/정산 API에서 최상위 메서드에 @Transactional이 없고, 내부 메서드에만 REQUIRES_NEW가 있을 때 발생하는 패턴이다.

**탐지 방법**:
```bash
# 배치 최상위 메서드에 @Transactional이 없는지 확인
grep -rn "fun process\|fun execute\|fun settle\|fun batch" \
  src/ --include="*.kt" --include="*.java" -B 5 | \
  grep -v "@Transactional" | grep "fun "

# REQUIRES_NEW 사용 위치에서 외부 메서드 @Transactional 확인
grep -rn "REQUIRES_NEW" src/ --include="*.kt" --include="*.java" -B 10 | \
  grep -v "@Transactional"

# 배치 API에 분산 락(Redis) 가드가 있는지 확인
grep -rn "fun.*[Bb]atch\|fun.*[Ss]ettle" src/ --include="*.kt" --include="*.java" -A 5 | \
  grep "redis\|lock\|setnx\|tryLock"
```

**위험 패턴**:
```kotlin
// ❌ 취약: 최상위에 @Transactional 없음, 동시 호출 시 중복 처리 가능
fun processAll(items: List<Item>) {        // @Transactional 없음
    items.forEach { processOne(it) }       // 동시 호출 시 같은 item 중복 처리 가능
}

@Transactional(propagation = REQUIRES_NEW)
fun processOne(item: Item) {
    // item 상태를 PROCESSING으로 먼저 변경하지 않음
    val data = itemRepository.findById(item.id)   // SELECT (잠금 없음)
    externalApi.process(data)
    data.status = COMPLETED
    itemRepository.save(data)
    // 동시 호출 A, B가 모두 SELECT → 둘 다 COMPLETED로 저장 → 중복 처리
}
```

**안전한 구조 — 처리 전 상태 선점**:
```kotlin
// ✅ 안전: SELECT FOR UPDATE로 행 잠금 + 상태 선점
@Transactional(propagation = REQUIRES_NEW)
fun processOne(item: Item) {
    val locked = itemRepository.findByIdForUpdate(item.id)  // SELECT FOR UPDATE
    if (locked.status != PENDING) return                     // 이미 처리된 항목 건너뜀
    locked.status = PROCESSING                               // 상태 선점
    itemRepository.save(locked)                              // 즉시 커밋 (REQUIRES_NEW)
    // 이후 처리...
    locked.status = COMPLETED
    itemRepository.save(locked)
}
```

**추가 확인 — 배치 API 동시 실행 가능 여부**:
```bash
# 배치 컨트롤러에 @Acl, @Session, 분산 락 없는 엔드포인트
grep -rn "@PostMapping\|@GetMapping" src/ --include="*.kt" -B 5 | \
  grep -i "batch\|settle\|process" | \
  grep -v "@Acl\|@Session\|@Lock"
```

**판단 기준**:

| 조건 | 판정 |
|---|---|
| 최상위 배치 메서드 @Transactional 없음 + 내부 REQUIRES_NEW만 있음 | **취약** (원자성 보장 없음) |
| 배치 API 동시 호출 방지 분산 락 없음 | **취약** (중복 실행 가능) |
| 처리 항목 상태를 PROCESSING으로 먼저 변경하지 않음 | **취약** (Race Window 존재) |
| SELECT FOR UPDATE + 상태 선점 후 처리 | 안전 |


## Part B — 결제/구매 횟수 제한 TOCTOU 보충 (AUTH_VULN_ANALYSIS Step 8)

> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L355-385 (원문 보존, 익명화 적용)

---

### Step 8 — Race Condition (TOCTOU) 점검

결제/구매 횟수 제한이 있는 API에서 검증과 저장이 원자적으로 처리되는지 확인한다.

#### 취약 구조 패턴:

```kotlin
// Controller — 취약 구조
fun joinApi(...) {
    val item = service.getValidItem(...)   // ① 검증 (@Transactional 없음 또는 별도)
    service.joinItem(item, ...)            // ② 저장 (@Transactional 별도)
}
```

#### 확인 포인트:

1. 검증(READ)과 저장(WRITE)이 **동일한 `@Transactional` 범위** 안에 있는가?
2. 검증 쿼리에 `SELECT FOR UPDATE` (행 잠금)이 있는가?
3. UNIQUE CONSTRAINT 등 DB 수준 중복 방지가 있는가?

```bash
# Repository에서 FOR UPDATE 사용 여부
grep -rn "FOR UPDATE\|forUpdate\|LockModeType.PESSIMISTIC" src/ --include="*.kt" --include="*.java" --include="*.xml"

# @Transactional readOnly 설정 확인 (readOnly=true면 쓰기 불가)
grep -rn "@Transactional" src/ --include="*.kt" | grep "readOnly"
```

---


## Part C — 익명화 사례 (A-03)

> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L501-521 (원문 보존, 익명화 적용)

### A-03: Race Condition — 구매 제한 우회 (TOCTOU)

**위치**: `GroupBuyJoinService.kt` — `getValidGroupBuy()` (L81), `joinGroupBuy()` (L45)

**원인**: 구매 횟수 검증(READ)과 이력 INSERT가 서로 다른 트랜잭션으로 분리되어 있어, 두 요청이 동시에 검증을 통과할 수 있음.

```
요청 A: countMemberPurchase() = 0 → 검증 통과
요청 B: countMemberPurchase() = 0 → 검증 통과 (A의 INSERT 이전)
요청 A: INSERT PAYMENT_COMPLETED
요청 B: INSERT PAYMENT_COMPLETED ← 제한 초과!
```

**핵심 결함**: 단순히 두 메서드를 하나의 `@Transactional`로 묶는 것만으로는 부족. DB 레벨 `SELECT FOR UPDATE` (비관적 잠금) 또는 UNIQUE CONSTRAINT가 없으면 동일 트랜잭션 내에서도 Repeatable Read 격리 수준에서 Race가 발생할 수 있음.

**완전한 대응방안**:
1. `SELECT ... FOR UPDATE` (비관적 잠금)으로 검증과 저장을 원자적으로 처리
2. 또는 `(groupBuySeq, mbrId)` UNIQUE CONSTRAINT + 애플리케이션 레벨 재시도 로직
3. 또는 Redis 분산 락 (`SETNX` 또는 Redisson `RLock`)

---


## Part D — Race Condition 체크리스트 (AUTH_VULN_ANALYSIS)

> 📎 원본: `4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)` L621-625 (원문 보존, 익명화 적용)

### Race Condition 체크리스트

- [ ] 횟수/수량 제한이 있는 API에서 검증과 저장이 동일 트랜잭션 내에 있는가?
- [ ] 해당 트랜잭션에서 `SELECT FOR UPDATE` 또는 비관적 잠금을 사용하는가?
- [ ] DB 수준의 UNIQUE CONSTRAINT 또는 분산 락이 적용되어 있는가?
