## Module M4 — logic-race (TOCTOU · 트랜잭션 원자성 · 배치 동시성 · 보상 트랜잭션)

**실행 조건**: `auth_map.module_plan.M4.run == true`
**Auto-Scan 연결**: `scan_toctou_patterns`(`--skip toctou`) — 후보만 생성 (`result: "정보"`, `needs_review: true`). RULE-1에 따라 전건 Read로 확인 후 TP/FP 판정.
**finding category**: `RACE_CONDITION`
**ID 접두어(task26_llm.json)**: `AUTH-RACE-NNN`

> 근거 원본 (원문 보존본): `methodology/race_condition_methodology.md`
> - Part A STEP 1~7, §3 판단 기준표 P1~P9, §4 수정 위치 결정 트리, §5 보고서 작성 가이드, §6 체크리스트, 부록 패턴 A~E
> - Part B (AUTH Step 8 — 결제/구매 횟수 제한 TOCTOU 보충)
> - Part C 익명화 사례 A-03 (구매 제한 우회)
> - Part D Race Condition 체크리스트
> 판정이 애매하면 위 원문 절을 직접 읽고 판단한다.

> **입력**: M3 C-3의 `auth_access_assessment.m4_handoff[]`가 있으면 그 엔드포인트를 D-1 대상 목록에 먼저 넣는다.
> **RULE-2 대상**: P2 / P3 / P6 / P8 / P9는 스크립트 탐지 정확도가 낮다. 아래 grep을 LLM이 직접 실행하고 코드를 따라가 판정한다.

---

### D-1. 핵심 API 식별 (Race STEP 1)

```bash
grep -rn "@PostMapping\|@PutMapping\|@DeleteMapping" src/ --include="*.kt" --include="*.java" | grep -i "purchase\|buy\|cancel\|refund\|issue\|point\|coupon\|payment\|order\|charge"
grep -rn "@GetMapping" src/ --include="*.kt" --include="*.java" | grep -i "apply\|register\|confirm\|execute\|process"
```

식별된 각 엔드포인트에 D-2~D-7을 순서대로 적용한다.

**[추가] 상태 변경 GET (원본 STEP 1 "GET이지만 상태를 변경하는 잘못된 설계")**:
GET 핸들러가 저장/수정/삭제/발급을 수행하면 D-2 이후 대상에 넣고, 해당 finding의 `manual_review_note`에 "상태 변경 GET — 재시도·프리페치·링크 공유로 중복 실행 가능"을 기록한다. GET 자체만으로는 finding을 만들지 않는다 (taxonomy에 해당 category 없음). 쿠키 인증 구조라면 M2 B-1(CSRF) 판정에 사실을 넘긴다.

### D-2. @Transactional 범위 분석 (Race STEP 2, P1/P3)

```bash
grep -rn "fun " src/ --include="*.kt" -A 5 | grep -v "@Transactional" | grep "repository\.save\|repository\.delete\|repository\.update\|\.save(\|\.delete("
grep -rn "public\|private\|protected" src/ --include="*.java" -B 3 | grep -v "@Transactional" | grep "repository\.save\|repository\.delete"
grep -rn "Propagation.REQUIRES_NEW\|propagation = Propagation" src/ --include="*.kt" --include="*.java"
```

**판정**: `@Transactional` 없이 검증(SELECT)+실행(INSERT/UPDATE)이 한 메서드에 존재 → **RACE_CONDITION(P1), 취약, High**. 외부 메서드 `@Transactional` 없음 + 내부만 `REQUIRES_NEW` → **RACE_CONDITION(P3), 취약, High**.

**[추가] propagation 판정표 (원본 2-2)**:

| 외부 @Transactional | 내부 propagation | 판정 |
|---|---|---|
| 없음 | REQUIRES_NEW | **취약 (P3)** — 외부에서 원자성 보장 안 됨 |
| 있음 | REQUIRES_NEW | 내부는 독립 트랜잭션, 외부 롤백이 내부에 영향 안 줌 → 설계 의도 확인 필요. finding 없이 `evidence_trail[]`에 기록, 금전 처리면 `manual_review_note`에 "부분 커밋 가능" 메모 |
| 있음 | REQUIRED (기본값) | 양호 — 같은 트랜잭션 공유 |
| 없음 | 없음 | **취약 (P1)** — 완전한 비트랜잭션 환경 |

**[추가] 판정 보강 (원본 2-1 "더 정확한 방법", §6 Phase 2, Part B)**:
- grep은 후보 추출용이다. 파일을 Read로 열어 ① 클래스/메서드 레벨 `@Transactional` ② 그 메서드의 쓰기 호출 ③ 같은 메서드 안의 검증 로직 순서로 확인한다.
- **클래스 레벨 `@Transactional` override**: 클래스에 `@Transactional`이 있어도 메서드에 `@Transactional(propagation = NOT_SUPPORTED/NEVER)` 또는 `readOnly = true`가 따로 붙어 있으면 메서드 설정이 우선한다. 메서드 레벨 설정을 반드시 확인한다.
- **`readOnly = true`**: 쓰기 메서드에 `readOnly = true`가 붙어 있으면 의도한 원자성 범위가 아니다. 검증 메서드만 `readOnly`이고 저장은 다른 트랜잭션이면 원본 Part B 취약 구조(검증과 저장이 다른 트랜잭션)로 본다.
  ```bash
  grep -rn "@Transactional" src/ --include="*.kt" --include="*.java" | grep "readOnly\|NOT_SUPPORTED\|NEVER"
  ```
- **프록시 우회 (self-invocation)**: 같은 클래스 내부에서 `this.method()`로 호출된 `@Transactional` 메서드는 Spring 프록시를 거치지 않아 트랜잭션이 적용되지 않는다. 호출자가 비트랜잭션이면 P1로 본다. `private` 메서드에 붙은 `@Transactional`도 같다.
- **Controller에서 검증과 저장을 따로 호출** (원본 Part B 취약 구조): `service.getValidItem()` → `service.joinItem()`처럼 두 서비스 호출이 각각 별도 트랜잭션이면 P1에 준해 **취약, High**.

### D-3. SELECT-then-Act 패턴 (Race STEP 3, P2/P4)

```bash
grep -rn "fun has\|fun exists\|fun check\|fun validate\|fun verify\|fun isValid\|fun isDuplicate" src/ --include="*.kt" --include="*.java"
grep -rn "\.count()\|\.exists()\|countBy\|existsBy\|SELECT COUNT" src/ --include="*.kt" --include="*.java" --include="*.xml"
grep -rn "findBy\|findAll\|selectBy" src/ --include="*.kt" --include="*.java" -A 10 | grep "\.save(\|\.insert\|\.update\|repository\."
```

**판정**: count/exists 체크 후 INSERT, 원자성 보장 없고 UNIQUE CONSTRAINT도 없음 → **RACE_CONDITION(P4), 취약, High**. `@Transactional`이 있어도 SELECT에 `FOR UPDATE` 없으면 동시 읽기 허용 상태 → D-4로 확인 후 **RACE_CONDITION(P2), 취약, Medium~High**.

**[추가] 확인 절차 (원본 STEP 3)**: ① 체크 메서드를 호출하는 서비스 메서드를 찾는다 ② 그 메서드에 `@Transactional`이 있는지 ③ 있어도 SELECT에 `FOR UPDATE`가 없으면 여전히 취약.
**P2 심각도**: 대상이 금전·포인트·쿠폰·수량 제한이면 High, 그 외(중복 신청 등 데이터 정합성만)면 Medium.

### D-4. SELECT FOR UPDATE 사용 여부 (Race STEP 4)

```bash
grep -rn "@Lock\|LockModeType\|PESSIMISTIC_WRITE\|PESSIMISTIC_READ" src/ --include="*.kt" --include="*.java"
grep -rn "FOR UPDATE\|for update\|forUpdate\|NOWAIT\|SKIP LOCKED" src/ --include="*.kt" --include="*.java" --include="*.xml" --include="*.sql"
grep -rn "@Query" src/ --include="*.kt" --include="*.java" -A 3 | grep -i "for update\|pessimistic"
```

**[추가] FOR UPDATE 필요성 판정표 (원본 STEP 4)**:

| 상황 | FOR UPDATE 필요 여부 |
|---|---|
| 동시 요청이 같은 행을 검증 후 수정 | **필요** |
| 배치 처리에서 여러 행을 순차 처리 | 행 단위 FOR UPDATE 또는 분산 락 필요 |
| 단순 조회 후 다른 테이블에 INSERT | 조회 테이블에 FOR UPDATE 필요 |
| UNIQUE CONSTRAINT로 DB가 중복을 막음 | FOR UPDATE 없이도 가능 (단, 예외 처리 필요) |

- `PESSIMISTIC_READ`(공유 락)는 검증 후 쓰기 구조에서 동시 읽기를 막지 못한다. 쓰기 구조면 `PESSIMISTIC_WRITE`인지 확인한다.
- 원본 사례 A-03 "핵심 결함": 두 메서드를 하나의 `@Transactional`로 묶는 것만으로는 부족하다. FOR UPDATE 또는 UNIQUE CONSTRAINT가 없으면 같은 트랜잭션 안에서도 Race가 발생할 수 있다 → P2로 판정.

### D-5. 예외 묵살 · 보상 트랜잭션 (Race STEP 5, P5/P8)

```bash
grep -rn "catch" src/ --include="*.kt" --include="*.java" -A 3 | grep -v "throw\|rethrow\|log\.\|logger\." | grep "}"
grep -rn "} catch\|} finally" src/ --include="*.kt" --include="*.java" -B 2 -A 5
grep -rn "fun cancel\|fun refund\|fun rollback\|fun revert" src/ --include="*.kt" --include="*.java" -A 30 | grep -B 5 "restTemplate\|WebClient\|feignClient\|\.call(\|\.send("
grep -rn "} catch\|} finally" src/ --include="*.kt" --include="*.java" -B 2 -A 8 | grep -B 5 "externalApi\|restTemplate\|\.call(\|paymentApi\|pointApi"
```

**판정**: `catch` 블록에 `throw`/`return` 없이 후속 로직 계속 실행 → **RACE_CONDITION(P5), 취약, Medium**. 외부 API(결제/포인트) 호출이 `@Transactional` 없는 취소/환불 메서드에서 DB 저장과 혼재 → **RACE_CONDITION(P8), 취약, High**. `catch`+`finally`에서 동일 외부 API 이중 호출 → **RACE_CONDITION(P8), 취약, High**.

**[추가] P8 판정표 (원본 부록 패턴 D)**:

| 조건 | 판정 |
|---|---|
| @Transactional 없음 + 외부 API + DB 저장 혼재 | **취약** |
| catch 블록 예외 묵살 + finally에서 동일 외부 API 재호출 | **취약** (이중 호출) |
| 외부 API 실패 시 rethrow 없이 후속 DB 저장 실행 | **취약** |
| 외부 API 실패 → 즉시 예외 throw, DB 롤백 | 양호 |

- `log.error()`만 하고 진행하는 catch도 묵살로 본다 (원본 STEP 5 예시). grep의 `grep -v "log\."`은 후보 축소용이므로 로그만 있는 catch는 Read로 따로 확인한다.
- `@Transactional`이 있어도 외부 API 호출은 롤백되지 않는다. 외부 호출 성공 후 DB 실패 시 보상(취소 API 호출) 경로가 있는지 확인한다. 없으면 P8.

### D-6. 배치/정산 동시성 (Race STEP 6, P6/P7/P9)

```bash
grep -rn "@Scheduled\|@PostMapping\|@GetMapping" src/ --include="*.kt" --include="*.java" | grep -i "batch\|settlement\|schedule\|process\|execute\|job"
grep -rn "forEach\|for (\|\.map {" src/ --include="*.kt" --include="*.java" -B 5 | grep -v "@Transactional" | grep "repository\.\|service\."
grep -rn "redisService\.\|redisTemplate\.\|RedisTemplate" src/ --include="*.kt" --include="*.java" | grep -i "put\|set\|get\|exists\|lock"
grep -rn "fun process\|fun execute\|fun settle\|fun batch" src/ --include="*.kt" --include="*.java" -B 5 | grep -v "@Transactional" | grep "fun "
grep -rn "REQUIRES_NEW" src/ --include="*.kt" --include="*.java" -B 10 | grep -v "@Transactional"
grep -rn "fun.*[Bb]atch\|fun.*[Ss]ettle" src/ --include="*.kt" --include="*.java" -A 5 | grep "redis\|lock\|setnx\|tryLock"
grep -rn "@PostMapping\|@GetMapping" src/ --include="*.kt" -B 5 | grep -i "batch\|settle\|process" | grep -v "@Acl\|@Session\|@Lock"
```

**판정**: 배치 `@Transactional` 없는 `forEach`/`map` 반복 처리 → **RACE_CONDITION(P7), 취약, High**. Redis 기록만 있고 get→check 가드 없음 → **RACE_CONDITION(P6), 취약, Medium**. 배치 최상위 `@Transactional` 없음 + 내부만 `REQUIRES_NEW` + 분산 락 없음 → **RACE_CONDITION(P9), 취약, High**.

**[추가] P9 판정표 (원본 부록 패턴 E)**:

| 조건 | 판정 |
|---|---|
| 최상위 배치 메서드 @Transactional 없음 + 내부 REQUIRES_NEW만 있음 | **취약** (원자성 보장 없음) |
| 배치 API 동시 호출 방지 분산 락 없음 | **취약** (중복 실행 가능) |
| 처리 항목 상태를 PROCESSING으로 먼저 변경하지 않음 | **취약** (Race Window 존재) |
| SELECT FOR UPDATE + 상태 선점 후 처리 | 양호 |

**[추가] 판정 보강 (원본 STEP 6 추가 항목, §6 Phase 5·6)**:
- **상태 선점**: 처리 대상 SELECT 직후(또는 SELECT FOR UPDATE와 함께) 상태를 `PROCESSING` 등으로 바꾸는 UPDATE가 있는지 확인한다. 처리 완료 후에만 상태를 바꾸면 그 사이가 Race Window다.
- **재실행 시 건너뛰기**: 이미 처리된 항목을 상태 조건으로 제외하는지(`WHERE status = 'READY'` 등) 확인한다.
- **Redis 가드 순서 (P6)**: 중복 방지 목적의 Redis 사용이 `get → check → set` 순서의 가드인지, 처리 후 기록만 하는지 구분한다. `get`과 `set`이 분리된 경우도 두 요청이 동시에 `get`을 통과할 수 있으므로, `SETNX`/`setIfAbsent`/Redisson `tryLock`처럼 **원자적 선점**인지 확인한다. 분리된 get→set은 P6 **취약, Medium**, 원자적 선점 + TTL + 해제 처리(finally)면 양호.
  ```bash
  grep -rn "setIfAbsent\|setnx\|SETNX\|tryLock\|RLock\|opsForValue().get" src/ --include="*.kt" --include="*.java" -B 2 -A 5
  ```
- **배치 API 인증**: 배치 엔드포인트에 `@Session`/`@Acl`이 없으면 그 자체는 M2 A-3에서 판정한다. M4에서는 "외부에서 동시 호출 가능 여부"의 근거로만 `manual_review_note`에 연결한다.
- **`@Scheduled` 다중 인스턴스**: 스케줄러가 여러 인스턴스에서 같이 돌 수 있는 구조(ShedLock 등 없음)인지 확인한다. 인스턴스 수가 이 repo에서 확인되지 않으면 `needs-dynamic-verification` → DAST 후보(`kind: "race_condition"`).
  ```bash
  grep -rn "@SchedulerLock\|ShedLock\|LockProvider" src/ --include="*.kt" --include="*.java"
  ```

### D-7. DB 수준 안전장치 (Race STEP 7)

```bash
grep -rn "@UniqueConstraint\|@Column(unique\|UNIQUE INDEX\|unique = true" src/ --include="*.kt" --include="*.java" --include="*.xml"
grep -rn "@Version" src/ --include="*.kt" --include="*.java"
grep -rn "UNIQUE\|unique" src/ --include="*.sql" -i
```

| 안전장치 | 효과 | 한계 |
|---|---|---|
| DB UNIQUE CONSTRAINT | 중복 INSERT를 DB가 차단 | 예외 처리 코드 필요, UPDATE 중복엔 미적용 |
| @Version (낙관적 락) | 동시 수정 감지 후 예외 발생 | 재시도 로직 필요, 충돌 빈도 높으면 성능 저하 |
| SELECT FOR UPDATE (비관적 락) | 행 단위 잠금으로 동시 접근 차단 | 데드락 위험, 성능 저하 가능 |
| 분산 락 (Redis/Zookeeper) | 서버가 여러 대여도 단일 진입 보장 | 인프라 의존성, 락 해제 실패 시 교착 |

UNIQUE CONSTRAINT/`@Version`/FOR UPDATE/분산락 중 무엇도 없으면 D-2~D-6 판정을 확정한다. 하나라도 있으면 실질적 가드로 동작하는지(예외 처리 유무, get→check 순서, UNIQUE 대상 컬럼이 중복 기준과 같은지) 확인 후 완화 여부를 `manual_review_note`에 기록한다.
- DDL이 이 repo에 없고(외부 DB 관리) Entity 어노테이션도 없으면 UNIQUE 존재 여부를 확정할 수 없다 → finding은 유지하되 `needs-dynamic-verification` + DAST 후보, `why_not_static`에 "DDL이 repo 외부에 있음".

---

### D-8. verification_status 기준

| 상황 | verification_status |
|---|---|
| 트랜잭션 부재·REQUIRES_NEW 단독·예외 묵살·이중 호출이 코드로 명확 | `code-confirmed` |
| 판정이 DB 격리 수준, DDL, 인스턴스 수, 외부 락 설정에 좌우됨 | `needs-dynamic-verification` → `dast_candidates_AUTH.json`에 `kind: "race_condition"` 후보 기록 |

**패턴별 분기 기준 (v2 추가)** — 같은 패턴이라도 D-7 안전장치를 이 repo에서 확인할 수 있는지에 따라 갈린다.

| 패턴 | `code-confirmed` 조건 | `needs-dynamic-verification` 조건 | 양호(finding 없음) 조건 |
|---|---|---|---|
| P1 트랜잭션 없는 검증+실행 | 메서드·호출자 모두 트랜잭션 없음을 Read로 확인, 같은 기준의 UNIQUE·락이 repo에 없음이 확인됨 (Entity/DDL이 repo 안에 있음) | DDL이 repo 밖이라 UNIQUE 존재를 확정할 수 없음 | 중복 기준 컬럼에 UNIQUE + 예외 처리 확인 |
| P2 FOR UPDATE 부재 | 대상 테이블에 UNIQUE·`@Version`·분산 락 모두 없음이 확인되고 격리 수준 설정이 repo에 있음 | 격리 수준이 DB 기본값(설정 없음)이거나 DDL이 repo 밖 | FOR UPDATE / `PESSIMISTIC_WRITE` / `@Version`+재시도 |
| P3 REQUIRES_NEW 단독 | 외부 트랜잭션 부재가 호출 경로 전체에서 확인됨 | 호출자가 다른 repo·메시지 리스너 등 이 repo 밖 | 외부 `@Transactional` 존재 (설계 의도는 `evidence_trail` 기록) |
| P4 COUNT/EXISTS 후 INSERT | 중복 기준 UNIQUE 부재가 Entity/DDL로 확인됨 | DDL이 repo 밖 | UNIQUE + `DataIntegrityViolationException` 처리 |
| P5 예외 묵살 | catch 후 후속 로직 실행이 코드로 명확 — **항상 정적 확정** | — | catch에서 throw/return |
| P6 Redis 가드 부재 | get/set 분리 또는 기록만 있음이 코드로 명확 | 가드가 공통 라이브러리·다른 모듈에 있어 구현을 볼 수 없음 | `setIfAbsent`/`SETNX`/`tryLock` + TTL + finally 해제 |
| P7 배치 반복 무트랜잭션 | 반복문·트랜잭션 부재가 코드로 명확 — **항상 정적 확정** | — | 건당 트랜잭션 또는 청크 트랜잭션 |
| P8 보상 트랜잭션 미구현 | 외부 API 실패/성공 후 DB 실패 경로에 보상 호출 없음이 코드로 명확 | 외부 API 측 멱등성 보장 여부(외부 서비스 문서·설정)가 판정에 필요 | 실패 시 즉시 throw + 보상 경로 존재 |
| P9 배치 중복 실행 | 최상위 트랜잭션·상태 선점·락 부재가 코드로 명확하고 배치 호출 경로가 repo 안에 있음 | 스케줄러 인스턴스 수, 외부 스케줄러(잡 플랫폼) 중복 방지 설정이 repo 밖 | FOR UPDATE + 상태 선점 + 분산 락(또는 ShedLock) |

- 판정이 `code-confirmed`이면 DAST 후보에 올리지 않는다.
- `needs-dynamic-verification`이면 `why_not_static`에 위 표의 해당 조건(예: "DDL이 repo 밖")을 그대로 쓴다.
- 양호 조건의 안전장치가 있어도 동작을 확인하지 못했으면(예외 처리 코드 미확인) 완화로 보고 D-7 규칙대로 `manual_review_note`에 기록한다.

DAST 후보에는 `code_signals`(트랜잭션 경계, 락/UNIQUE 유무, 검증·저장 위치)와 `why_not_static`만 적는다. 동시 요청 재현 절차는 쓰지 않는다 (`references/dast_candidates.md` §3).

### D-9. 보고서 작성 (원본 §4 / §5 매핑)

- **title**: `비즈니스 로직 우회 - [기능명] - [취약 원인]` (원본 명명 규칙)
  예) `비즈니스 로직 우회 - 쿠폰 발급 - TOCTOU(Time-of-Check to Time-of-Use)`, `비즈니스 로직 우회 - 정산 배치 - 트랜잭션 원자성 미보장`
- **description**: 원본 "취약 근거" 3요소를 순서대로 쓴다 — ① 어느 위치에 `@Transactional`이 없는지 ② SELECT가 FOR UPDATE 없이 실행되는 이유 ③ 개념 시나리오 (Thread A / Thread B 순서와 결과, 원본 사례 A-03 형식). 개념 시나리오는 코드 흐름 설명이며 요청 재현 절차가 아니다.
- **code_snippet**: 5~15줄 이내.
- **manual_review_note**: 적용 패턴 번호 (`P1`~`P9`) 필수 기록.
- **recommendation**: 원본 수정 위치 결정 트리를 따른다.
  1. `@Transactional`이 없음 → `@Transactional` 추가 검토
  2. 있음 + SELECT에 FOR UPDATE 없음 → `SELECT FOR UPDATE`(또는 `@Lock(PESSIMISTIC_WRITE)`) 추가 검토
  3. 있음 + FOR UPDATE 있음 + UNIQUE 없음 → DB UNIQUE CONSTRAINT 추가 검토
  4. 모두 있음 → 예외 처리 추가 검토
  단기(`@Transactional` + FOR UPDATE) / 장기(UNIQUE, 분산 락, 낙관적 락)로 나눠 쓰고, 각 방법의 주의사항(원본 §4 표: FOR UPDATE는 `@Transactional`과 함께 필수, UNIQUE는 `DataIntegrityViolationException` 처리 필요, 분산 락은 TTL·해제 실패 처리)을 함께 적는다.

---

### M4 판정 요약표 (summary_auth.md 「모듈별 판정 요약」에 채움 — 원본 §3 / Part D 체크리스트 매핑)

| # | 점검 항목 | 양호 기준 | 취약 기준 | 위험도 |
|---|---|---|---|---|
| P1 | 검증+실행 트랜잭션 | 같은 `@Transactional` 범위 | SELECT + INSERT/UPDATE가 `@Transactional` 없이 존재 | High |
| P2 | 동시 읽기 차단 | FOR UPDATE / PESSIMISTIC_WRITE | `@Transactional`만 있고 FOR UPDATE 없음 | Medium~High |
| P3 | REQUIRES_NEW | 외부 `@Transactional` 존재 | 외부 없음 + 내부 REQUIRES_NEW 단독 | High |
| P4 | 중복 체크 | UNIQUE CONSTRAINT 또는 원자적 처리 | COUNT/EXISTS 후 INSERT, UNIQUE 없음 | High |
| P5 | 예외 처리 | catch에서 throw/return | catch 후 후속 로직 계속 | Medium |
| P6 | Redis 가드 | 원자적 선점(SETNX/tryLock) | 기록만 있음 또는 분리된 get→set | Medium |
| P7 | 배치 반복 처리 | 건당 트랜잭션 보장 | `@Transactional` 없는 forEach/map | High |
| P8 | 외부 API 보상 | 실패 시 즉시 throw, 보상 경로 존재 | 외부 API + DB 저장 혼재, 이중 호출 | High |
| P9 | 배치 중복 실행 | FOR UPDATE + 상태 선점 + 분산 락 | 최상위 트랜잭션 없음 + REQUIRES_NEW 단독 + 락 없음 | High |
| — | 횟수/수량 제한 API (Part D) | 검증·저장 동일 트랜잭션 + FOR UPDATE 또는 UNIQUE/분산 락 | 하나라도 없음 | High |
| — | 상태 변경 GET | 없음 | 존재 (finding 없이 note) | — |
