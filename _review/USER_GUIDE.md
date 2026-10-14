# sec-scan-auth v2 — 사용자 가이드

> **상태: 임시 경로에만 존재. palantir 레포에는 반영되지 않았다.**
> palantir의 `sec-scan-auth` 파일 3개(SKILL.md / task_26 / commands)는 작업 전 백업과 md5가 같다 (마지막 확인 2026-10-14).
> 반영은 사용자가 명시적으로 승인할 때만 한다. 반영 전에 validator 선행 과제(F-2)가 먼저 끝나야 한다 (§6).

| 판 | 일자 | 내용 |
|---|---|---|
| 1판 | 2026-10-14 | v2 모듈 구조 최초 정리 |
| 2판 | 2026-10-14 | 외부 검토 의견 반영: auth_map 출처·재사용 조건, IDOR 소유권 검증 3분류, M4 정적/동적 분기표, 의도적 제외 목록, validator 선행 조건 |

---

## 1. 파일 위치

루트: `D:\100. ㅊㅇㅇ\sec-scan-auth_v2\`

palantir 레포와 **같은 상대 경로 구조**로 만들어 두었다. 반영할 때 그대로 같은 위치에 복사하면 된다.

```
D:\100. ㅊㅇㅇ\sec-scan-auth_v2\
├── .claude\commands\
│   └── sec-scan-auth.md                    ← /sec-scan-auth 슬래시 명령 (수정본)
├── sec-scan-auth\
│   ├── SKILL.md                            ← 오케스트레이터 (수정본)
│   └── references\
│       ├── task_prompts\
│       │   └── task_26_auth_review.md      ← 공통 규칙 허브 (수정본)
│       ├── modules\                        ← 신규: 실제 점검 절차·판정 기준
│       │   ├── m0_auth_recon.md            (구조 파악 → auth_map.json, 판정 없음)
│       │   ├── m1_authn.md                 (인증 강제·세션·Fail-Open·토큰 전달구조)
│       │   ├── m2_authz_acl.md             (IDOR·배치/관리자·Spring Security·@Acl·IP ACL)
│       │   ├── m3_stepup_mfa.md            (PIN 재검증·2차 인증 코드 신호)
│       │   ├── m4_logic_race.md            (TOCTOU·트랜잭션·배치 동시성, P1~P9)
│       │   └── m5_webview_client.md        (앱 ↔ 웹뷰 세션 전달·앱 토큰 저장)
│       ├── methodology\                    ← 신규: 원본 MD 5종 원문 보존본 (익명화)
│       │   ├── auth_methodology.md
│       │   ├── acl_methodology.md
│       │   ├── race_condition_methodology.md
│       │   ├── webview_session_methodology.md
│       │   └── intentional_exclusions.md   (의도적 제외 목록 + 결정 ID)
│       └── dast_candidates.md              ← 신규: 동적 확인 후보 파일 형식
└── _review\                                ← 검토용 (palantir에 반영하지 않음)
    ├── USER_GUIDE.md                       ← 이 문서
    ├── CHANGES.md                          ← 변경 내역·반영 전 검토 포인트 (R-1 ~ R-6)
    ├── COVERAGE_MATRIX.md                  ← 원본/v1 내용이 v2 어디로 갔는지
    ├── HANDOFF.md                          ← 세션 이어하기 메모
    ├── coverage_report.txt                 ← 원본 라인 누락 검증 결과
    ├── structure_report.txt                ← 구조 정합성 검증 결과
    ├── original\                           ← v1 원본 백업 3개
    └── tools\                              ← 생성·검증 스크립트
        ├── build_methodology.py
        ├── verify_coverage.py              (의도적 제외 목록을 읽어 검증)
        └── verify_structure.py
```

원본 MD (입력, 수정하지 않음):

| 키 | 경로 |
|---|---|
| AUTH | `D:\5. Skills\4. AUTH(DAST)_VULN_ANALYSIS.md` (= `D:\5. Skills\MySkills\5. AUTH_VULN_ANALYSIS.md`) |
| AUTHP5 | `D:\5. Skills\MySkills\Auth_Analysis.md` |
| ACL | `D:\5. Skills\MySkills\ACL_Analysis.md` |
| RACE | `D:\5. Skills\MySkills\6. RACE_CONDITION_ANALYSIS.md` |
| WEBVIEW | `D:\5. Skills\MySkills\WEBVIEW_SESSION_ANALYSIS.md` (= `D:\5. Skills\5. webview-auth-session-analysis.md`) |

---

## 2. 지금까지 한 작업

### 목표
palantir `sec-scan-auth` skill에 사용자 MD 7개(실질 5종)의 인증/인가 진단 내용을 **빠짐없이** 반영한다.
동적 진단에서 확인할 것들도 코드 레벨에서 미리 파악할 수 있게 한다. 단, palantir에 바로 반영하지 않는다.

### 진행 순서

| 단계 | 내용 | 결과물 |
|---|---|---|
| 1 | 원본 5종을 원문 그대로 옮기고 고객사 식별정보를 익명화 | `methodology/` 4개 |
| 2 | 원본 라인 누락 기계 검증 | `coverage_report.txt` — 1,532라인 누락 0 |
| 3 | 구조 개편 결정: 진입점 하나 + 모듈 분리, 기존 출력 틀 유지 | — |
| 4 | M0 구조 파악 모듈 | `m0_auth_recon.md` |
| 5 | M1 인증, M2 인가·ACL 모듈 (v1 task_26 A/B절 이동 + 원본 누락 기준 보강) | `m1_authn.md`, `m2_authz_acl.md` |
| 6 | M3 — 사용자 결정 **1-a**: 2차 인증·문자 인증은 코드 신호만 기록 | `m3_stepup_mfa.md` |
| 7 | DAST 후보 — 사용자 결정 **2 (축소 방식)** | `dast_candidates.md` |
| 8 | M4 동시성 모듈 (v1 task_26 C절 이동 + 원본 판정표 보강) | `m4_logic_race.md` |
| 9 | M5 웹뷰 모듈 (원본 WEBVIEW 3~7장) | `m5_webview_client.md` |
| 10 | task_26을 공통 규칙 허브로 재작성 | `task_26_auth_review.md` |
| 11 | SKILL.md를 오케스트레이터로 재작성 | `SKILL.md` |
| 12 | 슬래시 명령 파일 수정 | `.claude/commands/sec-scan-auth.md` |
| 13 | 구조 정합성 검증 스크립트 작성·실행 | `structure_report.txt` — 오류 0 |
| 14 | 반영 위치 매트릭스, 변경 내역, 사용자 가이드 | `COVERAGE_MATRIX.md`, `CHANGES.md`, 이 문서 |
| 15 | **외부 검토 의견 반영** (아래 표) | M0 / M2 / M4, `intentional_exclusions.md`, `verify_coverage.py`, `CHANGES.md` R-6 |

### 15단계 — 외부 검토 의견 처리 결과

| # | 의견 | 처리 | 반영 위치 |
|---|---|---|---|
| 1 | DAST 후보에 재현 입력값 추가 | **반영 안 함** — 결정 D-2 유지 (근거: `CHANGES.md` R-6) | — |
| 2 | IDOR: 검증 코드가 있어도 동적에서만 확인되는 경우 | **부분 반영** — 소유권 검증 3분류. 간접 검증은 동적 확인 후보로 분리, 코드 신호만 기록 | M2 A-5 |
| 3 | `auth_map.json` 출처 필드 | **반영** — `source` | M0 스키마 |
| 4 | 의도적 제외와 실수 누락 구분 | **반영** — `intentional_exclusions.md` + 검증 스크립트 연동 | `methodology/`, `verify_coverage.py` |
| 5 | 오래된 `auth_map.json` 재사용 방지 | **반영** — 커밋·해시·스코프 비교 후 재사용 | M0 R-7 |
| 6 | validator를 반영 선행 과제로 | **반영** — 반영 절차 선행 조건 | `CHANGES.md` §8 |
| 질문 | P1~P9 중 무엇이 동적 확인 후보가 되는가 | **반영** — 패턴별 분기표 | M4 D-8 |

### 사용자 결정 사항

| ID | 결정 | 내용 |
|---|---|---|
| — | DAST 후보 저장 | 별도 파일 `dast_candidates_AUTH.json`. 공유 스키마·`approve_report.py`는 수정하지 않음 |
| — | 실제 사례 | 익명화해서 포함 (사례 A-01 ~ A-07) |
| — | 대상 스택 | Spring Boot / Kotlin 유지 |
| D-1a | 2차 인증·문자 인증 | 코드에서 보이는 사실만 기록. 우회 판정·테스트 절차·finding 없음 |
| D-2 | DAST 후보 내용 | 코드 신호 / 정적으로 확정할 수 없는 이유 / 관련 finding만. 테스트 절차·재현 입력값 없음 (2026-10-14 재검토 후 유지) |
| — | `validate_findings.py` 문제 | 이번 작업과 분리, 별도 과제. 단 palantir 반영 전에 먼저 처리 |
| — | palantir 반영 | **하지 않음** |

결정 ID(D-1a, D-2 등)는 `methodology/intentional_exclusions.md` 「결정 ID」 표와 같다.

### 검증 결과 (2판 기준)

| 검증 | 결과 |
|---|---|
| 원본 라인 누락 (`verify_coverage.py`) | 1,532라인 검사, 누락 0, 식별정보 잔존 0 — **PASS** |
| 의도적 제외 목록 정합성 | 표 A 2건 (목차), 생성기 제외 목록과 일치 — 행을 빼면 FAIL 나는 것을 음성 테스트로 확인 |
| 구조 정합성 (`verify_structure.py`) | 파일·경로·category·판정 문구·교차 참조 74건·`--skip` 값·summary 섹션 — 오류 0, **PASS** |
| 출력 스키마 | v2 추가 필드로 인한 validator 신규 오류 0 (기존 갭 2건은 F-2) |

### 검증 중 발견한 것
- v1 task_26의 `task_25_data_protection.md` 참조 경로가 틀려 있었다 → v2에서 정정 (F-1).
- `shared/scripts/validate_findings.py`는 v1부터 `AUTH-` ID와 auth category를 허용하지 않는다 → 별도 과제, **palantir 반영의 선행 조건** (F-2).

---

## 3. 이 기능 이해하기

### 3-1. 한 문장
`/sec-scan-auth`를 실행하면 먼저 **이 서비스에 어떤 인증 흐름이 있는지** 파악한다. 그다음 **해당되는 점검 모듈만** 돌려서 인증·인가 취약점을 코드 근거와 함께 보고한다. 코드만으로 결론 낼 수 없는 것은 그렇다고 표시하고 따로 모은다.

### 3-2. v1과 무엇이 다른가

| | v1 | v2 |
|---|---|---|
| 점검 범위 | task_26 한 파일의 A/B/C절 전부 | M0가 구조를 보고 필요한 모듈만 선택 |
| 웹뷰 / 모바일 앱 | 거의 없음 (grep 1줄) | M5 전용 모듈 |
| PIN / 2차 인증 | PIN 재검증만 | PIN 재검증 + 2차 인증 코드 신호 기록 |
| 원본 판정표 | 일부만 반영 | 원본 표·사례 전부 반영 + 원문 보존본 참조 |
| 정적으로 확정 못 하는 것 | 표시 없음 | `verification_status`로 표시하고 동적 확인 후보 파일로 분리. IDOR·동시성은 분기 기준표 있음 |
| 재실행 | — | 같은 커밋·스코프일 때만 구조 지도 재사용 |
| 원본 반영 추적 | — | 의도적 제외 목록 + 결정 ID |
| 결과 파일 / category / ID | task26_llm.json, findings_AUTH.json, summary_auth.md / 9종 / `AUTH-` | **동일** (+ `auth_map.json`, `dast_candidates_AUTH.json`) |

### 3-3. 모듈 구성

```
/sec-scan-auth <repo>
   │
   ├─ Phase 1  자산 식별 (기존과 동일)
   │
   ├─ Phase 2  M0 auth-recon ──→ auth_map.json
   │             · 기존 맵이 있으면: 커밋·스코프 같을 때만 재사용, 다르면 재생성 (R-7)
   │             · repo 유형 (backend / mobile-client / web-frontend / mixed)
   │             · 존재하는 인증 흐름 (PIN? 2차 인증? 결제? 배치? IP ACL? 웹뷰?)
   │             · 민감 엔드포인트 목록
   │             · 어떤 모듈을 실행할지 (module_plan)
   │
   ├─ Auto-Scan  scan_auth_access_control.py (실행 안 하는 모듈의 항목은 --skip)
   │
   ├─ LLM-Check  실행 대상 모듈만 순서대로
   │     M1 authn         인증이 강제되는가 (누락·Fail-Open·테스트 세션·토큰 전달구조)
   │     M2 authz-acl     권한이 맞는가 (IDOR·배치/관리자·Spring Security·@Acl·IP ACL)
   │     M3 stepup-mfa    결제 전 PIN을 서버가 다시 확인하는가 / 2차 인증 코드 신호
   │     M4 logic-race    동시 요청에 안전한가 (트랜잭션·락·배치 중복)
   │     M5 webview       앱이 웹뷰에 세션을 안전하게 넘기는가
   │
   └─ Summary  summary_auth.md + dast_candidates_AUTH.json + 완료 요약 출력 후 대기
```

**모듈 실행 조건**

| 모듈 | 실행되는 경우 | 실행 안 될 때 기록 |
|---|---|---|
| M0 | 항상 | — |
| M1, M2 | 백엔드 repo | 해당없음(백엔드 아님) |
| M3 | PIN·2차 인증·결제/수량 흐름이 있음 | 해당없음(PIN/2차인증/결제 흐름 없음) |
| M4 | 결제/수량·배치·Redis 가드·상태를 바꾸는 GET이 있음 | 해당없음(금전/수량/배치 흐름 없음) |
| M5 | 모바일 앱 repo이거나 웹뷰 세션 전달 구조가 있음 | 해당없음(Webview 구조 없음) |

- 프론트엔드 전용 repo → 모듈 전부 skip (v1과 같음)
- 모바일 앱 repo → M5만 실행

### 3-4. 판정이 어디서 오는가
- **판정 기준** = 모듈 파일 (`modules/m1~m5`). 각 절에 grep 명령과 "어떤 코드면 어떤 category·심각도"가 적혀 있다.
- **공통 규칙** = `task_26_auth_review.md`. 마스킹, 후보 확인 의무, 심각도 표, 출력 형식이 있다.
- **원문 근거** = `methodology/`. 판정이 애매할 때 LLM이 해당 절만 읽는다. 사람도 "이 기준이 원본 어디서 왔나"를 여기서 확인할 수 있다.
- **원본에서 뺀 것** = `methodology/intentional_exclusions.md`. 무엇을 왜 뺐는지(결정 ID)가 있다.
- 각 모듈 상단의 「근거 원본」에 어느 원문 절을 참조하는지 적혀 있다.

### 3-5. 코드만으로 확정하는 것 vs 동적 확인 후보로 넘기는 것

모든 finding에 `verification_status`가 붙는다.

| 값 | 뜻 | 결과 |
|---|---|---|
| `code-confirmed` | 이 repo의 코드·설정만으로 취약 조건을 확인함 | finding만 |
| `needs-dynamic-verification` | 결론이 배포 설정·인프라·외부 서비스·repo 밖 코드에 달려 있음 | finding + `dast_candidates_AUTH.json`에 후보 1건 |

이 분기가 특히 중요한 두 영역은 판정 기준을 표로 고정해 두었다.

**IDOR — 소유권 검증 3분류 (M2 A-5)**

| 상태 | 코드에서 본 것 | 처리 |
|---|---|---|
| 검증 없음 | 요청 ID를 세션과 대조하지 않고 그대로 조회·수정·삭제에 사용 | 취약, `code-confirmed` |
| 간접 검증 | 소유권 확인이 공통 처리기·AOP·외부 API·DB 정책 등 메서드 밖에 있어 경로 전체를 확인하지 못함 | 정보, `needs-dynamic-verification` → 동적 확인 후보 |
| 직접 검증 | 서비스 레이어에서 세션 ID 비교 또는 `WHERE`에 세션 ID 사용 확인 | 양호 |

**동시성 — 패턴별 분기 (M4 D-8 요약)**

| 패턴 | 코드만으로 확정되는 경우 | 동적 확인 후보가 되는 경우 |
|---|---|---|
| P1 / P4 (트랜잭션 없는 검증+실행, COUNT 후 INSERT) | Entity/DDL이 repo 안에 있어 UNIQUE 부재까지 확인됨 | DDL이 repo 밖 |
| P2 (FOR UPDATE 부재) | UNIQUE·`@Version`·락 부재 + 격리 수준 설정 확인 | 격리 수준이 DB 기본값이거나 DDL이 repo 밖 |
| P3 (REQUIRES_NEW 단독) | 호출 경로 전체가 repo 안 | 호출자가 다른 repo·메시지 리스너 |
| P5 / P7 (예외 묵살, 배치 반복 무트랜잭션) | **항상 코드만으로 확정** | — |
| P6 (Redis 가드) | get/set 분리가 코드로 보임 | 가드 구현이 공통 라이브러리 등 repo 밖 |
| P8 (보상 트랜잭션) | 보상 호출 부재가 코드로 보임 | 외부 API 멱등성 확인이 필요 |
| P9 (배치 중복 실행) | 트랜잭션·상태 선점·락 부재 + 호출 경로가 repo 안 | 스케줄러 인스턴스 수·외부 잡 플랫폼 설정이 repo 밖 |

동적 확인 후보에는 **대상, 코드 신호, 코드만으로 확정 못 하는 이유, 관련 finding**만 적는다. 테스트 방법·재현 입력값은 적지 않는다 (결정 D-2).

### 3-6. 구조 지도(`auth_map.json`)의 출처와 재사용

- `source`: 맵을 어디서 만들었는지. 이 skill은 항상 `static-code`(소스코드)로 만든다.
  `openapi-spec`, `behavioral-observed`, `mixed`는 나중에 다른 수단으로 같은 형식의 맵을 만들 수 있게 자리만 잡아 둔 예약 값이다.
- 코드가 아닌 출처의 맵을 받으면 모듈 실행 계획만 참고하고, `code-confirmed`는 코드를 직접 읽어 확인한 항목에만 붙인다.
- `source_ref`: 맵을 만들 때의 repo 커밋(`repo_commit`), `.git`이 없을 때 쓰는 소스 해시(`source_hash`), 진단 스코프(`scope`).
- 재실행 시 이 값이 현재와 모두 같을 때만 재사용한다. 하나라도 다르거나 확인할 수 없으면 다시 만든다.

### 3-7. 용어

| 용어 | 뜻 |
|---|---|
| `auth_map.json` | M0가 만든 서비스 인증 구조 지도. 이후 모듈이 이걸 보고 대상만 점검 |
| `module_plan` | auth_map 안의 모듈별 실행 여부와 사유 |
| `source` / `source_ref` | 맵의 출처 / 맵을 만든 시점의 커밋·해시·스코프 |
| `verification_status` | `code-confirmed` = 코드만으로 확정 / `needs-dynamic-verification` = 코드만으로 확정 불가 |
| 동적 확인 후보 | `needs-dynamic-verification` 항목과 2차 인증 흐름 목록. 진단자가 동적 진단 대상을 고를 때 참고 |
| 코드 신호 | 코드에서 관찰한 사실 (예: 검증 위치, 시도 제한 유무, 객체 참조 파라미터 이름). 취약 여부 판단이 아님 |
| 간접 검증 (IDOR) | 소유권 확인이 대상 메서드 밖에 있어 실제 적용 여부를 코드로 끝까지 확인하지 못한 상태 |
| 의도적 제외 | 원본 내용 중 결정에 따라 뺀 것. `intentional_exclusions.md`에 사유·결정 ID와 함께 기록 |
| 결정 ID | D-1a, D-2, D-STRUCT, D-BOUND — 무엇을 왜 뺐는지 추적하는 번호 |
| P1~P9 | 원본 RACE 문서의 동시성 취약 패턴 번호 |

---

## 4. 사용 방법

> ⚠️ 아래 4-1은 **palantir에 반영한 뒤의 사용법**이다. 현재는 반영하지 않았으므로 palantir에서 `/sec-scan-auth`를 실행하면 **v1이 동작한다.**

### 4-1. 기본 실행 (반영 후)

```
# 1. 소스 준비 (기존과 동일, Windows PowerShell)
python3 tools/clone_repo.py <PROJECT_KEY> <REPO_SLUG>

# 2. 진단 — 해당 모듈 자동 선택
/sec-scan-auth <repo>

# 3. 특정 모듈만 (예: PIN·동시성만 다시 볼 때)
/sec-scan-auth <repo> --only M3,M4

# 4. 결과 검토 (사용자가 직접 실행 — 자동 실행되지 않음)
/sec-review <RUN_ID> <repo>
```

- 실행 중에는 확인 질문 없이 끝까지 진행한다 (CLAUDE.md 자율 완주).
- 끝나면 요약을 출력하고 **멈춘다.** `/sec-review`는 사용자가 실행한다.
- `--only`를 써도 M0는 항상 실행한다. 기존 `auth_map.json`은 커밋·스코프가 같을 때만 재사용하고, 콘솔에 재사용/재생성 사유가 한 줄 나온다.

### 4-2. 반영하지 않고 미리 보고 싶을 때
palantir 레포를 건드리지 않는 방법:
1. **문서로 검토**: `CHANGES.md` §5 검토 포인트(R-1 ~ R-6) → `COVERAGE_MATRIX.md` → 관심 있는 모듈 파일 순서로 읽는다.
2. **별도 복사본에서 시험 실행**: palantir 레포를 다른 폴더(예: `D:\test\palantir-v2test\`)로 통째로 복사하고, 그 복사본에만 staging 파일을 덮어써서 실행한다. 원본 palantir는 그대로 남는다. 요청하면 진행한다.
   - 이때 `findings_AUTH.json`을 `validate_findings.py`로 검증하면(`docs/tutorial_single_repo_scan.md`의 스키마 검증 단계) validator 갭(F-2) 때문에 `AUTH-` ID·category 오류 2종이 나온다. v1도 같은 상태라, 시험 실행에서는 알려진 실패로 보면 된다.

### 4-3. 결과를 읽는 순서

| 순서 | 파일 | 볼 것 |
|---|---|---|
| 1 | `state/<prefix>/summary_auth.md` | 통계, finding 목록(모듈·검증상태 열), 모듈별 판정 요약 |
| 2 | 〃 「인증 아키텍처 요약」 | 서비스가 세션을 어떻게 검증·전달하는지 (헤더 키 이름, 검증 방식, 웹뷰 전달 방식) |
| 3 | 〃 「동적 확인 후보」 | 코드만으로 확정 못 한 항목과 이유 → 동적 진단 대상 선정에 참고 |
| 4 | `/sec-review` | finding별 정탐/오탐 판정 (기존과 동일) |
| 필요 시 | `findings_AUTH.json` | finding 상세 (`source_module`으로 어느 모듈에서 나왔는지 확인) |
| 필요 시 | `dast_candidates_AUTH.json` | 동적 확인 후보 상세 (코드 신호) |
| 필요 시 | `auth_map.json` | 왜 어떤 모듈이 실행/미실행됐는지, 어느 커밋 기준인지 |

### 4-4. 검증 스크립트 다시 돌리기 (문서 수정 후)

```bash
cd /c/Users/skplanet
py -3 -I "/d/100. ㅊㅇㅇ/sec-scan-auth_v2/_review/tools/verify_coverage.py"  "D:/100. ㅊㅇㅇ/sec-scan-auth_v2"
py -3 -I "/d/100. ㅊㅇㅇ/sec-scan-auth_v2/_review/tools/verify_structure.py" "D:/100. ㅊㅇㅇ/sec-scan-auth_v2" "D:/5. Skills/MySkills/palantir-main (1)/palantir-main"
```
- `python`은 WindowsApps 스텁이라 실패하므로 `py -3`을 쓴다.
- 두 번째 스크립트는 palantir 레포를 **읽기만** 한다 (스크립트 choices 확인, validator 실행). 아무것도 쓰지 않는다.
- 결과: `_review/coverage_report.txt`, `_review/structure_report.txt`. 끝에 `판정: PASS ✅`가 나오면 정상이다.
- `structure_report.txt` S9의 「기존 갭」 2건은 validator 별도 과제(F-2)이며 오류로 세지 않는다.

### 4-5. 원본 내용을 일부러 뺄 때 (판정 기준 조정 시)

`CHANGES.md` R-2/R-3의 항목을 조정하다가 원본 내용을 빼야 하면, 이 순서를 지킨다. 그래야 검증 스크립트가 "실수로 빠진 것"과 "일부러 뺀 것"을 구분한다.

1. `methodology/intentional_exclusions.md`에 행을 먼저 추가한다
   - 원문 라인을 빼는 경우 → 표 A (`원본키 | 시작라인 | 끝라인 | 사유 | 결정 ID`)
   - 원문은 두고 판정 범위만 줄이는 경우 → 표 B
   - 새 결정이면 「결정 ID」 표에도 추가
2. 해당 내용을 수정·삭제한다
3. 4-4의 검증 스크립트를 다시 돌린다 — 표 A에 없는 원문 라인이 빠져 있으면 "누락"으로 FAIL

판정 기준만 바꾸고 원문 보존본(`methodology/*.md`)은 그대로 두는 경우가 대부분이다. 이 경우 표 B만 갱신하면 된다.

---

## 5. 예상 결과

> 아래는 **형식 예시**다. v2는 아직 실제 repo로 실행해 보지 않았다 (`CHANGES.md` §6). 수치·경로는 가상이다.

### 5-1. 콘솔 출력 흐름 (백엔드 repo 예)

```
[M0] auth_map.json 재생성 — 사유: repo_commit 변경 (a1b2c3d → e4f5a6b)
[M0 auth-recon] auth_map.json 생성 완료
  repo_type : backend
  flows     : pin_step_up, payment_or_quota, batch_admin, ip_acl, redis_guard_signal
  모듈 계획 : M1 ✓ | M2 ✓ | M3 ✓ | M4 ✓ | M5 ✗(Webview 구조 없음)

[scan_auth_access_control v...] 진단 시작: testbed/<repo>
...
[M1 authn] 완료 — 취약 1 / 정보 0 / FP 2
[M2 authz-acl] 완료 — 취약 3 / 정보 1 / FP 5
[M3 stepup-mfa] 완료 — 취약 1 / 정보 0 / FP 1
[M4 logic-race] 완료 — 취약 2 / 정보 1 / FP 4

[Phase C-1] llm_data_access_log.json 업데이트 완료
  ...

[sec-scan-auth] 완료 — <repo>
  실행 모듈 : M0 M1 M2 M3 M4 (M5 해당없음)
  findings  : 취약 7 / 정보 2 (FP 제외 12)
  동적 후보 : 4건 → state/<prefix>/dast_candidates_AUTH.json
  요약      : state/<prefix>/summary_auth.md
  [다음 단계 — 사용자 지시 시] /sec-review <RUN_ID> <repo>
```

- 처음 실행이면 첫 줄 없이 바로 생성 완료가 나온다. 같은 커밋으로 다시 실행하면 `[M0] auth_map.json 재사용 — repo_commit e4f5a6b 일치`가 나온다.
- 모바일 앱 repo라면 `모듈 계획 : M1 ✗ | M2 ✗ | M3 ✗ | M4 ✗ | M5 ✓`가 되고 Auto-Scan은 건너뛴다.

### 5-2. 생성 파일 (`state/<prefix>/`)

| 파일 | v1 | v2 | 용도 |
|---|---|---|---|
| `task26_result.json` | ✓ | ✓ | 스크립트 자동 판정 원본 (증적, 수정 안 함) |
| `task26_llm.json` | ✓ | ✓ | LLM 판정 + `auth_access_assessment` |
| `findings_AUTH.json` | ✓ | ✓ | `/sec-review` 대상 (finding에 `source_module`, `verification_status` 추가) |
| `summary_auth.md` | ✓ | ✓ | 사람이 읽는 요약 (섹션 4개 추가) |
| `auth_map.json` | — | **신규** | 인증 구조 지도·모듈 실행 계획·출처(`source`)·기준 커밋(`source_ref`) |
| `dast_candidates_AUTH.json` | — | **신규** | 동적 확인 후보 (업로드·보고서 미연결) |

### 5-3. summary_auth.md 모양

```markdown
# 인증/인가 및 접근제어 취약점 진단 결과 요약 — sample-api

진단일: 2026-10-20 | 대상: <repo url> | LLM 검증: 완료
repo 유형: backend | 실행 모듈: M0 M1 M2 M3 M4 | 미실행: M5 (해당없음 — Webview 구조 없음)

## 결과 통계
| 카테고리 | 취약 | 정보 | 양호 |
| IDOR | 1 | 1 | 3 |
| PIN_REVERIFICATION_MISSING | 1 | 0 | 2 |
| RACE_CONDITION | 2 | 1 | 0 |
| ... |

## Finding 목록
| ID | 제목 | 위험도 | 카테고리 | 모듈 | 파일:라인 | 판정 | 진단방법 | 검증상태 |
| AUTH-001 | [PIN 검증 미흡] POST /api/v1/purchase/join | 4 고위험 | PIN_REVERIFICATION_MISSING | M3 | src/.../PurchaseController.kt:92 | 취약 | 교차검증(수동) | code-confirmed |
| AUTH-002 | 비즈니스 로직 우회 - 쿠폰 발급 - TOCTOU | 4 고위험 | RACE_CONDITION | M4 | src/.../CouponService.kt:45 | 취약 | 수동진단(LLM) | needs-dynamic-verification |
| AUTH-006 | IDOR — 주문 상세 조회 소유권 검증이 공통 Resolver에 위임됨 | 3 중위험 | IDOR | M2 | src/.../OrderController.kt:61 | 정보 | 수동진단(LLM) | needs-dynamic-verification |

## 인증 아키텍처 요약
- 유형: Stateful (세션ID → 외부 인증 서버)
- 세션 헤더 키: x-session-id (값 미기재)
- 인증 서버 호출 URL: 설정 키 auth.server.url (고정값)
- 쿠키: 미사용 / Gateway 내부 헤더 덮어쓰기: 클라이언트 헤더 제거 확인

## 모듈별 판정 요약
### M1 authn
| 점검 항목 | 결과 |
| 인증 강제 유형 | 양호 (Spring Security 전역) |
| 테스트 세션 우회 | 양호 (local 프로파일 게이팅) |
| 인증 서버 Fail-Open | 취약 (AUTH-005) |
| 세션 URL 노출 | 이상 없음 |
...
### M5 webview-client
해당없음(Webview 구조 없음)

## 2차 인증·문자 인증 코드 신호
| 흐름 | 서버 검증 위치 | 상태 저장 | 결합 | 만료 | 시도 제한 | 후속 확인 |
| 휴대폰 인증 | CertService.kt:88 | redis | user_id | TTL 180s | not_found | AccountController.kt:45 |

## 동적 확인 후보 (4건)
| candidate_id | 모듈 | kind | 대상 | 정적 확정 불가 사유 | 관련 finding |
| DAST-AUTH-001 | M2 | idor | GET /api/v1/order/{orderId} | 소유권 확인이 공통 Resolver에 있어 이 경로 적용 여부를 끝까지 확인 못 함 | AUTH-006 |
| DAST-AUTH-002 | M3 | stepup_mfa_flow | POST /cert/verify | 시도 제한이 이 repo에서 확인되지 않음 (인프라 제한 가능성) | [] |
| DAST-AUTH-003 | M4 | race_condition | POST /coupon/issue | DDL이 repo 외부에 있어 UNIQUE 존재 확정 불가 | AUTH-002 |
| ... |
```

### 5-4. 결과를 읽을 때 주의할 점
- **`needs-dynamic-verification`은 "취약 아님"이 아니다.** 코드에 위험 신호는 있지만 환경이나 repo 밖 코드에 따라 결론이 달라진다는 뜻이다. 동적 진단에서 확인할 대상이다.
- **IDOR "간접 검증"은 "양호"가 아니다.** 검증 코드가 어딘가 있지만 이 엔드포인트에 실제로 적용되는지 코드로 끝까지 따라가지 못했다는 뜻이다. `result: 정보`로 나온다.
- **2차 인증 표의 `not_found`는 "취약"이 아니다.** 이 repo에서 해당 코드를 찾지 못했다는 뜻이다. 다른 서비스나 인프라에서 처리할 수 있다.
- **동적 확인 후보 파일에는 테스트 방법이 없다.** 결정 D-2에 따라 대상·코드 신호·이유만 기록한다. 테스트 방법은 진단자가 정한다.
- **심각도가 taxonomy 기본값과 다르면** finding의 `manual_review_note`에 `severity 조정: A → B (사유: ...)`가 있다.
- **모든 finding은 `/sec-review`의 사람 판정을 거친다** (v1과 같음). LLM이 정탐으로 확정해도 `review_status`는 비어 있다.

---

## 6. 다음에 할 수 있는 일 (사용자 지시 시에만)

권장 순서대로 적었다. palantir 반영은 앞의 항목이 끝난 뒤에만 가능하다.

| 순서 | 항목 | 설명 |
|---|---|---|
| 1 | 검토 포인트 확인 | `CHANGES.md` §5 — R-2 심각도 14건, R-3 추가 판정 기준 13건, R-6 외부 검토 반영 결과. 빼거나 바꿀 항목이 있으면 4-5 절차로 조정 |
| 2 | 시험 실행 (선택) | palantir 복사본에서 실제 repo 1개로 실행해 모듈 선택·오탐·동적 후보 분류 확인 |
| 3 | **validator 선행 과제 (F-2)** | `validate_findings.py`에 `AUTH` 접두어·auth category 9종 추가. 별도 과제로 처리하고 `verify_structure.py` S9 「기존 갭」 0건 확인 |
| 4 | palantir 반영 | `CHANGES.md` §8 절차 (1~3 완료 후). **승인 전에는 하지 않음** |
