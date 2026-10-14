# DAST 후보 기록 형식 — `dast_candidates_AUTH.json`

> 사용자 결정 2 (축소 방식): **코드 신호 / 정적으로 확정 불가한 이유 / 관련 finding**만 기록한다.
> 실제 테스트 절차·요청 예시·페이로드·성공 판정 기준은 **작성하지 않는다**. 동적 확인 여부와 방법은 진단자가 결정한다.
> 사용자 결정 1-a: 이 파일은 공유 스키마(`output_schemas.md`)와 `approve_report.py`에 연결하지 않는 별도 산출물이다.

**출력 경로**: `state/<prefix>/dast_candidates_AUTH.json`
**생성 시점**: 모든 모듈(M1~M5) 분석이 끝나고 `task26_llm.json`을 쓴 직후. 후보가 0건이어도 빈 배열로 생성한다.
**업로드**: 하지 않는다. `findings_AUTH.json` 변환·`/sec-review`·최종 보고서 대상이 아니며 진단자 참고용이다.

---

## 1. 무엇을 후보로 올리는가

| 출처 | 조건 | `kind` |
|---|---|---|
| 모든 모듈 | finding의 `verification_status == "needs-dynamic-verification"` | finding의 category를 소문자로 (예: `auth_bypass`, `ip_acl_bypass`) |
| M3 C-2 | 2차 인증·문자 인증 흐름 1건당 1건 (finding 없음) | `stepup_mfa_flow` |
| M4 | RACE_CONDITION finding 중 동시 요청 영향이 인프라(다중 인스턴스·격리 수준·락 설정)에 좌우되는 것 | `race_condition` |
| M5 | 앱·웹뷰 경계에서 서버 코드만으로 확인 불가한 전달 구간 | `webview_session` |

- `code-confirmed` finding은 후보로 올리지 않는다 (정적으로 확정됨).
- FP로 판정되어 `evidence_trail[]`로 이동한 항목은 올리지 않는다.

## 2. 형식

```json
{
  "schema": "dast_candidates_auth/v1",
  "repo": "<repo>",
  "run_id": "<RUN_ID>",
  "generated_from": "state/<prefix>/task26_llm.json",
  "candidates": [
    {
      "candidate_id": "DAST-AUTH-001",
      "source_module": "M1",
      "kind": "auth_bypass",
      "target": {
        "endpoint": "POST /api/v1/order/cancel",
        "file": "src/main/kotlin/.../OrderController.kt",
        "line": 42
      },
      "code_signals": [
        "인증 서버 호출 타임아웃 시 예외 처리 분기가 외부 라이브러리 설정(auth.client.fallback)에 위임됨",
        "fallback 빈 정의가 이 repo에 없음"
      ],
      "why_not_static": "fallback 동작이 배포 설정에 따라 달라지며 이 repo에서 설정값을 확인할 수 없음",
      "related_findings": ["AUTH-BYP-003"]
    }
  ]
}
```

| 필드 | 필수 | 규칙 |
|---|---|---|
| `candidate_id` | ✓ | `DAST-AUTH-NNN`, 3자리 순번 |
| `source_module` | ✓ | `M1`~`M5` |
| `kind` | ✓ | 1절 표의 값 |
| `target.endpoint` | 엔드포인트가 있으면 | `METHOD /path` |
| `target.file` / `target.line` | ✓ | repo 상대 경로 |
| `code_signals` | ✓ | 코드에서 관찰한 사실 문장 배열. M3 C-2는 신호 키 객체(`{"server_verify_location": "...", ...}`)를 그대로 넣는다 |
| `why_not_static` | ✓ | 정적으로 확정할 수 없는 이유 한 문장 |
| `related_findings` | ✓ | 관련 finding ID 배열, 없으면 `[]` |

## 3. 작성 금지

- 테스트 절차, 요청/응답 예시, 페이로드, 도구 사용법, 성공/실패 판정 기준
- 세션값·토큰·인증번호·IP·도메인 등 원문 (RULE-3 마스킹 동일 적용)
- "취약함", "우회 가능" 같은 결론 문장 — 결론은 관련 finding 또는 진단자 판단에 둔다

## 4. summary_auth.md 반영

「동적 확인 후보」 절에 건수와 표를 넣는다. 열: `candidate_id` / 모듈 / kind / 대상 / 정적 확정 불가 사유 / 관련 finding.
0건이면 "동적 확인 후보 없음"으로 적는다.
