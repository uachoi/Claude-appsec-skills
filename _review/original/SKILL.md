---
name: sec-scan-auth
description: Modularized SAST skill for Authentication/Authorization/Access Control diagnosis — IDOR, admin/batch privilege escalation, global auth bypass (Fail-Open, test session backdoor), PIN/password re-verification, session/token exposure, Spring Security ACL misconfiguration, IP-based ACL bypass, internal API exposure, and TOCTOU race conditions. Runs scan_auth_access_control.py then LLM cross-verification. Use when asked to run auth/access-control scan, 인증/인가 진단, IDOR/권한탈취/ACL/동시성 취약점 분석 on a target in testbed/. Part of the broader sec-audit-static pipeline; future updates will include Jira integration.
tools: Read, Glob, Grep, Bash, Edit, Write, Agent, WebFetch
---

# Sec Scan Auth

## Overview
이 skill은 `sec-audit-static` 전체 파이프라인에서 **인증/인가 및 접근제어(IDOR / 관리자·배치 권한탈취 / 인증우회 / PIN 재검증 / 세션·토큰 노출 / ACL / TOCTOU)** 진단만을 담당하는 모듈입니다.

독립 실행 가능: `sec-scan-auth/` + `shared/scripts/scan_auth_access_control.py`

향후 Jira 연동 기능이 추가될 예정입니다.

## Workflow

### Step 1: Load references

**로컬 (이 skill 전용)**
- `shared/references/task_prompts/task_11_asset_identification.md` - 자산 식별 절차
- `references/task_prompts/task_26_auth_review.md` - 인증/인가/ACL/TOCTOU LLM 검토 절차 (IDOR/권한탈취/AUTH_BYPASS/PIN/세션토큰노출/ACL/IP_ACL_BYPASS/내부API노출/RACE_CONDITION 판정기준)

**공유 (shared/)**
- `shared/references/workflow.md` - Phase/Task 실행 맵, 보안 정책
- `shared/references/output_schemas.md` - JSON 출력 스키마
- `shared/references/severity_criteria.md` - 위험도 매핑
- `shared/references/vuln_taxonomy.md` - 취약점 분류 표준 (Section 6 — 인증/인가 및 접근제어)
- `shared/references/cross_verification.md` - Phase 3-1 교차검증 + Phase 3-2 LLM 수동 심층진단 절차
- `shared/references/manual_review_prompt.md` - LLM 수동진단 페르소나, 진단기준, 답변원칙
- `shared/references/finding_writing_guide.md` - finding 품질 기준 (code_snippet 필수, 한국어 설명)
- `shared/references/tooling.md` - 코드 브라우저 도구 (rg/ctags)
- `shared/references/large_repo_multi_module.md` - 대형 repo / 멀티 모듈 진단 전략
- `shared/references/unsupported_lang_targets.md` - 자동 스캔 미지원 언어 (PHP 등)

### ⚠️ 사전 필수 — 소스코드 Clone

> testbed/ 에 소스코드가 없으면 진단을 시작할 수 없다.

```powershell
# Windows PowerShell에서 실행
python3 tools/clone_repo.py <PROJECT_KEY> <REPO_SLUG> [--branch BRANCH]
```

실행 결과로 `testbed/<repo>/` 에 소스코드가 준비된다. 진단 시 이 경로를 `<src>` 로 사용한다.

testbed/ 에 소스코드가 없으면 **위 명령을 직접 실행하고 clone 완료 후 진단을 이어서 진행**한다.

---

### 실행 원칙 (CRITICAL — 반드시 준수)

> **자율 완주 (Autonomous Execution)**: 실행 중에는
> "do you want to proceed?", "계속할까요?", "다음 단계로 진행할까요?" 등
> **어떠한 확인 질문도 하지 않는다.**
>
> - 자산 식별 → Auto-Scan → LLM-Check 전 구간을 중단 없이 진행한다.
> - 스크립트 실패·빌드 오류·파일 없음 등 예상 범위 내 오류는 fallback을 자동 적용하고 계속 진행한다.
> - 예외: 토큰/자격증명 누락처럼 사람만 해결할 수 있는 blocking 오류 발생 시에만 보고 후 대기한다.

### Step 2: Execute tasks

**Phase 1 — 자산 식별 (Asset Identification)**
- `shared/references/task_prompts/task_11_asset_identification.md` 절차 실행
- frontend/backend 판별, 언어/프레임워크 확인, Spring Security 설정 파일(`*SecurityConfig*`) 존재 여부 확인
- **프론트엔드 전용 repo(`.java`/`.kt` 파일 0건)이면 이 skill의 Auto-Scan/LLM-Check Phase 전량 skip** — 인증/인가/ACL/TOCTOU는 백엔드 서버 측 관심사이므로 프론트엔드 대응 진단 항목 없음. 결과에 "해당없음(프론트엔드 repo)" 기록.
- PHP 등 미지원 언어이면 Auto-Scan Phase skip 후 기록

**Auto-Scan Phase — 인증/인가/ACL/TOCTOU 정적 분석 (Python 스크립트)**

```bash
python3 shared/scripts/scan_auth_access_control.py <src> \
    -o state/<prefix>/task26_result.json \
    --api-inventory state/<prefix>/api_scan.json
```

> **API 인벤토리 권장**: `scan_api.py`(Task 2-1)가 선행 실행되어 있으면 `--api-inventory`로
> IDOR/권한탈취/내부API노출 진단의 엔드포인트 역추적이 강화된다.
> 없어도 단독 실행 가능하나 IDOR 후보 탐지 정확도가 낮아진다.

진단 항목 (백엔드 모드 — Java/Kotlin):
- **IDOR**: `@PathVariable`/`@RequestParam` ID 파라미터가 세션 사용자 대조 없이 조회/수정/삭제에 사용되는 후보 — LOW-confidence, `result: "정보"` + `needs_review: true` 고정
- **PRIVILEGE_ESCALATION / INTERNAL_API_EXPOSURE**: Batch/Admin/Internal/Manage 컨트롤러 중 `@Session`/`@Acl`/`@PreAuthorize`/`@Secured` 전부 누락
- **AUTH_BYPASS**: 전역 인증 필터/인터셉터 부재, Fail-Open 패턴(예외/타임아웃 시 인증 통과), 테스트 세션 우회 로직(TEST_ID 등)이 env 게이팅 없이 존재
- **PIN_REVERIFICATION_MISSING**: 결제/정보변경 API 중 `pinConfirmationDate`/`passwordConfirmationDate` 등 서버측 유효시간 재검증 필드 미참조
- **BROKEN_ACCESS_CONTROL**: Spring Security `permitAll()`/`antMatchers`/`requestMatchers` 과다 허용, 근거 불명 `csrf().disable()`
- **IP_ACL_BYPASS**: `getServerName()`/`getHeader("Host")` 기반 ACL 판정, IP 허용목록 `contains()` 부분매칭, X-Forwarded-For 미검증
- **RACE_CONDITION**: `@Transactional` 없는 검증+실행(P1), count/exists 후 insert(P4), 예외 묵살(P5), 배치 `@Transactional` 없는 forEach/map(P7) — regex 기반 후보 탐지, `needs_review: true` 고정

> **자동스캔 미탐지 한계**: `FOR UPDATE` 부재(P2), `REQUIRES_NEW` 단독 사용(P3/P9), Redis 가드 부재(P6),
> 보상 트랜잭션 미구현(P8)은 흐름 분석이 필요해 정규식 자동탐지 정확도가 낮다.
> `references/task_prompts/task_26_auth_review.md` Section C의 grep 절차로 LLM-Check 단계에서 직접 확인한다.

출력: `state/<prefix>/task26_result.json`

LLM 검토 절차는 `references/task_prompts/task_26_auth_review.md` 전체 절차 준수.

**LLM-Check Phase — 교차검증 + 수동 심층진단 (LLM)**
- **LLM-Check Phase 1** (자동판정 "취약"/"정보" 후보 건): `shared/references/cross_verification.md` LLM-Check Phase 1 절차
  - IDOR/RACE_CONDITION 후보는 반드시 코드 직접 확인 후 TP/FP 판정 (자동스캔은 후보 탐지만 수행)
  - FP는 `evidence_trail[]`로 이동
- **LLM-Check Phase 2** (자동탐지 불가 항목 — Auth 5-6/ACL 4-3 Vuln1-3/Race P2·P3·P6·P8·P9): `shared/references/cross_verification.md` LLM-Check Phase 2 + `manual_review_prompt.md`
  - `task_26_auth_review.md`에 명시된 grep 절차로 수동 심층진단 수행
  - 출력: `diagnosis_method: "수동진단(LLM)"` + `manual_review_note`

### Step 3: Output validation
- 모든 task 출력에 `metadata.source_repo_url`, `metadata.source_repo_path`, `metadata.source_modules` 포함 필수.
- JSON을 `shared/references/output_schemas.md` 스키마로 검증.

### Step 4: Summary 출력

LLM-Check Phase 완료 후 `state/<prefix>/summary_auth.md` 를 생성한다.

**읽을 파일**:
- `state/<prefix>/task26_result.json` — 스크립트 자동 판정 결과

**출력 형식**:

```markdown
# 인증/인가 및 접근제어 취약점 진단 결과 요약 — <repo명>

진단일: YYYY-MM-DD | 대상: <source_repo_url> | LLM 검증: 완료

## 결과 통계

| 카테고리 | 취약 | 정보 | 양호 |
|---|---|---|---|
| IDOR | N | N | N |
| PRIVILEGE_ESCALATION | N | N | N |
| AUTH_BYPASS | N | N | N |
| PIN_REVERIFICATION_MISSING | N | N | N |
| SESSION_TOKEN_EXPOSURE | N | N | N |
| BROKEN_ACCESS_CONTROL | N | N | N |
| IP_ACL_BYPASS | N | N | N |
| INTERNAL_API_EXPOSURE | N | N | N |
| RACE_CONDITION | N | N | N |
| **합계** | **N** | **N** | **N** |

## Finding 목록

| ID | 제목 | 위험도 | 카테고리 | 파일:라인 | 판정 | 진단방법 |
|---|---|---|---|---|---|---|
| AUTH-001 | IDOR — 주문 취소 API mbrId 세션 대조 누락 | 4 고위험 | IDOR | src/.../OrderController.java:88 | 취약 | 교차검증(수동) |

> 양호 항목은 목록에서 제외. 취약·정보만 기재.

## 소스 파일
- `state/<prefix>/task26_result.json`
```

**작성 규칙**:
- Finding 목록은 심각도 내림차순 (Critical → High → Medium → Low → Info)
- 카테고리는 위 9종으로 구분
- `evidence.file` + `evidence.lines` 에서 파일:라인 추출
- 양호는 통계에만 포함, 목록에는 미기재

### Step 4-1: LLM-Check 완료 확인 — 업로드 전 필수 게이트

> **HARD RULE**: `task26_llm.json` 미존재 상태로 업로드 금지.
> IDOR/AUTH_BYPASS/RACE_CONDITION 항목은 LLM 교차검증 없이 FP율이 매우 높다(정규식 후보 탐지 특성상).
> `findings_AUTH.json` 생성 시 반드시 `llm_checked: true` 설정.

업로드 전 확인:
```bash
python3 -c "
import pathlib, sys
prefix = 'state/<prefix>'
has_llm = pathlib.Path(f'{prefix}/task26_llm.json').exists()
findings = pathlib.Path(f'{prefix}/findings_AUTH.json')
if not has_llm:
    print('[BLOCK] task26_llm.json 없음 — LLM-Check 먼저 수행', file=sys.stderr); sys.exit(1)
if findings.exists():
    import json
    d = json.loads(findings.read_text())
    if not d.get('llm_checked', False):
        print('[BLOCK] findings_AUTH.json llm_checked=false', file=sys.stderr); sys.exit(1)
print('[OK] LLM-Check 완료 확인')
"
```

통과 조건 충족 후 Phase C-1을 수행한다.

### Step 4-2: 사람 판정 필드 침범 금지 (HARD RULE)

> **HARD RULE**: 이 skill(Auto-Scan/LLM-Check 어느 단계도)은 `reviewed`/`review_status` 필드를 직접 설정하지 않는다.
> 이 두 필드는 `/sec-review` §4의 사람 판정에서만 부여되며, `tools/audit_utils.py log-review` 호출로 `state/audit_log.json`에 기록되는 것만이 유효한 판정 경로다.
> LLM-Check가 TP로 확정한 finding이라도 `llm_verdict: "TP"` / `manual_review_note` 까지만 기록하고 `reviewed`/`review_status`는 미기재 상태로 남겨, 예외 없이 `/sec-review`를 거치도록 한다.

---

### Step C: Phase C-1 — LLM 데이터 접근 로그 업데이트

> **정책**: `shared/references/llm_data_cleansing_policy.md` | **절차**: `shared/references/phase_c_cleansing.md`

LLM-Check 완료 직후 수행. **testbed는 이 단계에서 삭제하지 않는다** (이후 sca 진단에 필요).
testbed 삭제 + Confluence 등록은 `/sec-review` 완료 시 Phase C-2에서 수행.

**수행**:

1. 이 세션에서 `testbed/<repo>/` 경로를 Read 도구로 접근한 파일 목록 정리 (Phase 1 / Phase 3 구분)
2. `state/<repo>/llm_data_access_log.json` 생성(없으면) 또는 `skills[]` 배열에 auth 항목 append:
   ```json
   {
     "skill": "auth",
     "scan_dir": "state/<repo>/auth/<YYYYMMDD_HHMM>",
     "scanned_at": "<진단 시작 ISO8601 +09:00>",
     "llm_accessed_files": [
       { "phase": "Phase 1 - Asset Identification", "purpose": "자산 식별", "files": ["testbed/<repo>/build.gradle", "..."] },
       { "phase": "Phase 3 - LLM-Check", "purpose": "교차검증", "files": ["testbed/<repo>/src/..."] }
     ]
   }
   ```
3. 신규 생성 시 `project`는 `state/<repo>/20*/scan_meta.json`의 `bb_project` 값 사용 (없으면 `"?"`)
4. `cleansing_completed: false` 유지

**완료 출력**:
```
[Phase C-1] llm_data_access_log.json 업데이트 완료
  skill  : auth
  접근파일: N건 (Phase 1: N / Phase 3: N)
  로그   : state/<repo>/llm_data_access_log.json
  [다음] /sec-review 완료 시 testbed 삭제 + Confluence 레지스트리 등록 수행
```

Phase C-1 완료 후 `/sec-review` 로 인터랙티브 정/오탐 판정을 진행한다.

## Resources

### 로컬 (이 skill 폴더 내)
- `shared/references/task_prompts/task_11_asset_identification.md`
- `references/task_prompts/task_26_auth_review.md`

### 공유 (shared/references/)
#### Workflow & Policy
- `workflow.md`, `output_schemas.md`, `severity_criteria.md`, `vuln_taxonomy.md`

#### Diagnosis Criteria
- `cross_verification.md`, `manual_review_prompt.md`

#### Tooling & Rules
- `tooling.md`
- `large_repo_multi_module.md`, `unsupported_lang_targets.md`
