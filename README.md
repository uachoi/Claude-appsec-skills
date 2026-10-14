# Claude-appsec-skills
Claude Code security skills for AppSec — static (SAST) and dynamic-oriented vulnerability analysis

## 포함된 skill

| skill | 상태 | 설명 |
|---|---|---|
| [`sec-scan-auth`](sec-scan-auth/SKILL.md) (v2) | 검토용 작업본 | 인증/인가·접근제어·동시성·웹뷰 세션 진단. 구조 파악(M0) 후 해당 모듈(M1~M5)만 실행 |

---

## sec-scan-auth v2 — 인증/인가 진단 skill 고도화 (작업본)

Claude Code용 SAST skill `sec-scan-auth`(palantir 보안 진단 모듈 모음의 인증/인가 진단 담당)의 **v2 개편 작업본**이다.
인증·인가·접근제어·동시성·웹뷰 세션 진단 방법론 문서 5종을 skill에 빠짐없이 반영하고, 하나의 진입점에서 **구조 파악 → 해당 모듈만 실행**하는 구조로 바꿨다.

> **상태: 검토용 작업본.** 원본 palantir 레포에는 반영하지 않았다. 실제 repo 대상 시험 실행도 아직 하지 않았다.

---

### 무엇을 하는 skill인가

`/sec-scan-auth <repo>`를 실행하면:

1. **M0 auth-recon**: 대상 서비스에 어떤 인증 흐름이 있는지 파악해 `auth_map.json`을 만든다 (repo 유형, PIN·2차 인증·결제·배치·IP ACL·웹뷰 흐름, 민감 엔드포인트, 실행할 모듈).
2. **Auto-Scan**: `scan_auth_access_control.py`로 후보를 찾는다 (실행하지 않는 모듈의 항목은 `--skip`).
3. **LLM-Check**: 해당하는 모듈만 순서대로 실행해 코드 근거로 판정한다.
4. **Summary**: `summary_auth.md`, `findings_AUTH.json`, `dast_candidates_AUTH.json`을 만들고 멈춘다.

| 모듈 | 점검 내용 | finding category |
|---|---|---|
| M0 auth-recon | 구조 파악, 모듈 실행 계획 (판정 없음) | — |
| M1 authn | 인증 강제, @Session, Fail-Open, 테스트 세션 우회, 세션/토큰 전달구조 | `AUTH_BYPASS`, `SESSION_TOKEN_EXPOSURE`, `INTERNAL_API_EXPOSURE` |
| M2 authz-acl | IDOR, 배치/관리자 권한, Spring Security, 커스텀 @Acl, IP ACL 우회 | `IDOR`, `PRIVILEGE_ESCALATION`, `BROKEN_ACCESS_CONTROL`, `IP_ACL_BYPASS`, `INTERNAL_API_EXPOSURE` |
| M3 stepup-mfa | PIN·비밀번호 서버측 재검증, 2차 인증 코드 신호 기록 | `PIN_REVERIFICATION_MISSING` |
| M4 logic-race | TOCTOU, 트랜잭션 범위, FOR UPDATE, 배치 동시성, 보상 트랜잭션 (P1~P9) | `RACE_CONDITION` |
| M5 webview-client | 앱 ↔ 웹뷰 세션 전달, 앱 토큰 저장, JS Bridge, 전송 채널 | `SESSION_TOKEN_EXPOSURE` |

### v1 대비 주요 변경
- 진입점 하나 + 모듈 분리. 서비스에 없는 흐름은 점검하지 않고 "해당없음(사유)"으로 기록
- 웹뷰/모바일 앱 전용 모듈(M5) 신설
- 모든 finding에 `verification_status`(`code-confirmed` / `needs-dynamic-verification`) 표시, 코드만으로 확정 못 하는 항목은 동적 확인 후보 파일로 분리
- IDOR 소유권 검증 3분류, 동시성 패턴별 정적/동적 분기표
- `auth_map.json` 출처(`source`)·기준 커밋(`source_ref`) 기록, 같은 커밋일 때만 재사용
- 결과 파일·category 9종·`AUTH-` ID 체계는 v1과 동일

### 설계 원칙
- **코드 근거만**: 판정은 Read로 확인한 코드에만 근거한다. 추측 금지.
- **판정과 신호의 분리**: 2차 인증·문자 인증은 코드 신호만 기록하고 판정하지 않는다 (결정 D-1a).
- **동적 확인 후보는 목록만**: 대상, 코드 신호, 정적으로 확정할 수 없는 이유, 관련 finding만 기록한다. 테스트 절차·재현 입력값은 쓰지 않는다 (결정 D-2).
- **민감정보 마스킹**: 세션값·토큰·내부 IP·호스트·PII 원문은 결과물에 남기지 않는다.

---

### 폴더 구조

```
.
├── README.md
├── .claude/commands/sec-scan-auth.md        슬래시 명령
├── sec-scan-auth/
│   ├── SKILL.md                             오케스트레이터
│   └── references/
│       ├── task_prompts/task_26_auth_review.md   공통 규칙 (HARD RULE, 심각도, 출력 형식)
│       ├── modules/                         M0 ~ M5 점검 절차·판정 기준
│       ├── methodology/                     원본 방법론 5종 원문 보존본 (익명화) + 의도적 제외 목록
│       └── dast_candidates.md               동적 확인 후보 파일 형식
└── _review/                                 검토 문서·검증 도구 (skill 실행에는 쓰이지 않음)
    ├── USER_GUIDE.md                        사용자 가이드 (먼저 읽을 문서)
    ├── CHANGES.md                           변경 내역, 반영 전 검토 포인트
    ├── COVERAGE_MATRIX.md                   원본/v1 내용의 반영 위치
    ├── HANDOFF.md                           작업 이어하기 메모
    ├── coverage_report.txt / structure_report.txt   검증 결과
    ├── original/                            v1 skill 파일 백업
    └── tools/                               methodology 생성·검증 스크립트
```

### 문서 읽는 순서

1. [`_review/USER_GUIDE.md`](_review/USER_GUIDE.md): 기능 이해, 사용법, 예상 결과
2. [`_review/CHANGES.md`](_review/CHANGES.md): 무엇이 바뀌었고 무엇을 검토해야 하는지 (R-1 ~ R-6)
3. [`sec-scan-auth/SKILL.md`](sec-scan-auth/SKILL.md) → [`references/modules/`](sec-scan-auth/references/modules/): 실제 절차

### 사용법 (palantir에 반영한 뒤)

이 작업본은 palantir 레포와 같은 상대 경로 구조다. 반영 시 `sec-scan-auth/`와 `.claude/commands/sec-scan-auth.md`를 palantir 루트의 같은 위치에 복사한다 (`_review/` 제외, 절차는 `CHANGES.md` §8).

```
/sec-scan-auth <repo>                  # 해당 모듈 자동 선택
/sec-scan-auth <repo> --only M3,M4     # 지정 모듈만 (M0는 항상 실행)
/sec-review <RUN_ID> <repo>            # 결과 검토는 사용자가 직접 실행
```

필요한 것: palantir 레포의 `shared/` (scripts, references), `tools/clone_repo.py`로 준비한 `testbed/<repo>/`.

### 생성 파일 (`state/<prefix>/`)
| 파일 | 내용 |
|---|---|
| `auth_map.json` | 인증 구조 지도, 모듈 실행 계획 (v2 신규) |
| `task26_result.json` | 스크립트 자동 판정 원본 |
| `task26_llm.json` | LLM 판정 |
| `findings_AUTH.json` | `/sec-review` 대상 finding |
| `summary_auth.md` | 사람이 읽는 요약 |
| `dast_candidates_AUTH.json` | 동적 확인 후보 (v2 신규, 보고서 미연결) |

### 검증

문서 정합성과 원본 반영 여부를 스크립트로 검증한다.

```bash
py -3 -I _review/tools/verify_coverage.py  <이 폴더 경로>
py -3 -I _review/tools/verify_structure.py <이 폴더 경로> <palantir 레포 경로>
```

| 검증 | 결과 |
|---|---|
| 원본 방법론 라인 누락 | 1,532라인, 누락 0, 식별정보 잔존 0 — PASS |
| 구조 정합성 (경로·category·판정 문구·교차 참조·`--skip` 값·summary 섹션) | 오류 0 — PASS |

- `verify_coverage.py`는 원본 방법론 MD 파일 경로가 코드에 고정되어 있어 작성 환경에서만 그대로 동작한다.
- `verify_structure.py`는 palantir 레포를 읽기만 한다.

### 알려진 한계 / 남은 과제

- **실제 repo 시험 실행 전**: 모듈 선택, grep 오탐·누락은 실제 진단으로 확인해야 한다.
- **validator 선행 과제 (F-2)**: palantir `shared/scripts/validate_findings.py`가 `AUTH-` ID와 auth category를 허용하지 않는다 (v1부터). palantir 반영 전에 별도로 처리해야 한다.
- **검토 포인트**: taxonomy 기본값과 다른 심각도 14건, 원본에 근거가 없는 추가 판정 기준 13건 (`CHANGES.md` R-2, R-3).
- 대상 스택은 Spring Boot / Kotlin 중심이다. M5는 Android / iOS / Flutter / React Native를 다룬다.

### 원본 출처

`sec-scan-auth/references/methodology/`는 아래 내부 방법론 문서를 원문 그대로 옮기고 고객사·서비스 식별정보를 익명화한 것이다. 사례(A-01 ~ A-07)는 익명화된 예시다.

| 키 | 문서 |
|---|---|
| AUTH | 인증/인가 취약점 분석 방법론 (DAST 관점 포함) |
| AUTHP5 | PHASE 5 Authentication & Authorization |
| ACL | PHASE 4 ACL (Access Control) |
| RACE | Race Condition 분석 방법론 (STEP 1~7, P1~P9) |
| WEBVIEW | Webview 인증 및 세션 관리 분석 방법론 |
