---
allowed-tools: Read, Glob, Grep, Bash, Edit, Write, Agent, WebFetch
description: 인증/인가/접근제어/동시성/웹뷰 세션(IDOR, 권한탈취, ACL, TOCTOU, PIN, Webview) 진단 — 구조 파악 후 해당 모듈만 실행
argument-hint: <repo> [--only M1,M2,M3,M4,M5]
---

# Sec Scan Auth

대상: $ARGUMENTS (미입력 시 testbed/ 내 대상 목록을 먼저 확인)

- 첫 번째 인자: `<repo>` (`testbed/<repo>/`)
- `--only M1,M3`: 지정 모듈만 실행 (M0는 항상 실행). 미지정 시 M0의 `module_plan` 전체 실행

## 실행 절차

`sec-scan-auth/SKILL.md` 전체 내용을 읽고 절차대로 실행할 것.

1. `sec-scan-auth/SKILL.md` 읽기
2. `shared/references/task_prompts/task_11_asset_identification.md` 읽기
3. `sec-scan-auth/references/task_prompts/task_26_auth_review.md` 읽기 (공통 규칙 허브)
4. `sec-scan-auth/references/modules/m0_auth_recon.md` 읽기
5. 공유 references (`shared/references/`) 필요 항목 읽기
6. SKILL.md Phase 1(자산 식별) → Phase 2(M0 → `auth_map.json`) → Auto-Scan → LLM-Check(모듈 순차) → Summary 순서대로 자율 완주
   - 모듈 파일(`references/modules/m1~m5`)은 `module_plan`에서 실행하는 것만 읽는다
   - `references/methodology/*.md`는 판정이 애매할 때 해당 절만 읽는다
7. 완료 요약 출력 후 대기 — `/sec-review` 등 다른 skill 자동 실행 금지
