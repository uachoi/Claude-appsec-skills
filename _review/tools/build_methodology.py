"""원본 방법론 MD 5종(중복 2쌍 제외)을 라인 범위 단위로 그대로 복사 + 익명화하여
sec-scan-auth/references/methodology/*.md 를 생성한다.

- 원문 재작성 없이 복사만 하므로 내용 손실/변형이 없다.
- 고객사 식별 정보는 ANON_MAP 으로 치환한다 (사례는 익명화 예시로 보존).
- 코드 펜스 밖의 마크다운 헤딩만 강등(demote)하여 Part 하위로 중첩시킨다.

사용: python -I build_methodology.py <staging_root>
"""
import json
import pathlib
import re
import sys

SRC = {
    "AUTH": r"D:\5. Skills\4. AUTH(DAST)_VULN_ANALYSIS.md",          # == MySkills\5. AUTH_VULN_ANALYSIS.md (md5 동일)
    "AUTHP5": r"D:\5. Skills\MySkills\Auth_Analysis.md",
    "ACL": r"D:\5. Skills\MySkills\ACL_Analysis.md",
    "RACE": r"D:\5. Skills\MySkills\6. RACE_CONDITION_ANALYSIS.md",
    "WEBVIEW": r"D:\5. Skills\MySkills\WEBVIEW_SESSION_ANALYSIS.md",  # == 5. webview-auth-session-analysis.md (md5 동일)
}

SRC_LABEL = {
    "AUTH": "4. AUTH(DAST)_VULN_ANALYSIS.md (= MySkills/5. AUTH_VULN_ANALYSIS.md, 동일 파일)",
    "AUTHP5": "MySkills/Auth_Analysis.md",
    "ACL": "MySkills/ACL_Analysis.md",
    "RACE": "MySkills/6. RACE_CONDITION_ANALYSIS.md",
    "WEBVIEW": "MySkills/WEBVIEW_SESSION_ANALYSIS.md (= 5. webview-auth-session-analysis.md, 동일 파일)",
}

# 순서 중요: 긴 식별자 → 짧은 식별자
def _load_local():
    """고객사 식별정보(치환표·금지어)는 저장소에 두지 않고 로컬 전용 파일에서 읽는다."""
    path = pathlib.Path(__file__).with_name("anon_map.local.json")
    if not path.exists():
        sys.exit(f"[BLOCK] {path.name} 없음 — 익명화 치환표는 저장소에 포함되지 않는다. 작성 환경의 로컬 파일을 같은 폴더에 두고 실행할 것")
    data = json.loads(path.read_text(encoding="utf-8"))
    return [tuple(p) for p in data["ANON_MAP"]], data["FORBIDDEN"]


ANON_MAP, FORBIDDEN = _load_local()

# 원본에서 의도적으로 복사하지 않는 라인 (사유 기록) — verify_coverage.py 가 동일 목록을 사용
EXCLUDED = {
    "AUTH": [(9, 16, "목차(TOC) — 재구성된 파일 구조로 대체")],
    "RACE": [(9, 16, "목차(TOC) — 재구성된 파일 구조로 대체")],
}


def anonymize(text: str) -> str:
    for old, new in ANON_MAP:
        text = text.replace(old, new)
    return text


def load(key):
    return pathlib.Path(SRC[key]).read_text(encoding="utf-8").splitlines()


HEADING = re.compile(r"^(#{1,6})(\s.*)$")


def excerpt(key, start, end, top_level=3):
    """원본 key 의 [start, end] (1-based, inclusive) 라인을 복사. 펜스 밖 헤딩을 top_level 기준으로 강등."""
    lines = load(key)[start - 1:end]
    in_fence = False
    levels = []
    for ln in lines:
        if ln.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        m = HEADING.match(ln)
        if m and not in_fence:
            levels.append(len(m.group(1)))
    shift = (top_level - min(levels)) if levels else 0
    out, in_fence = [], False
    for ln in lines:
        if ln.lstrip().startswith("```"):
            in_fence = not in_fence
            out.append(ln)
            continue
        m = HEADING.match(ln)
        if m and not in_fence and shift > 0:
            lvl = min(6, len(m.group(1)) + shift)
            ln = "#" * lvl + m.group(2)
        out.append(ln)
    body = anonymize("\n".join(out)).rstrip()
    tag = f"> 📎 원본: `{SRC_LABEL[key]}` L{start}-{end} (원문 보존, 익명화 적용)"
    return f"{tag}\n\n{body}\n"


def part(title, *chunks):
    return f"## {title}\n\n" + "\n\n".join(chunks) + "\n"


COMMON_NOTE = """> **이 파일의 위치와 우선순위**
> - 이 파일은 원본 진단 방법론을 **원문 그대로 보존**한 참조 자료다 (라인 단위 복사, 고객사 식별정보만 익명화).
> - 실행 절차·판정 심각도·출력 형식은 `references/task_prompts/task_26_auth_review.md`가 **우선**한다.
> - 원본의 "Output language", "Final Verdict Summary Table", "Finding Report Format" 지시는
>   task_26 「원본 방법론 출력 지시 매핑」 규칙에 따라 `task26_llm.json` / `summary_auth.md` / `dast_candidates_AUTH.json`으로 매핑된다.
> - 원본 사례(파일명·클래스명·IP·헤더명)는 익명화 예시다. 실제 진단 대상의 이름으로 간주하지 말 것.
"""


def build(root: pathlib.Path):
    out_dir = root / "sec-scan-auth" / "references" / "methodology"
    out_dir.mkdir(parents=True, exist_ok=True)

    files = {}

    files["auth_methodology.md"] = "\n".join([
        "# 인증/인가 진단 방법론 (Auth 5-1 ~ 5-6 + 사례/체크리스트)",
        "",
        COMMON_NOTE,
        "> task_26 연결: Section A (A-1 ~ A-7), Section E (DAST 후보)",
        "> 원본 메타: " + "분석 대상: [익명화] 고객사 Webview API 서비스 (Spring Boot + Kotlin)" + " / 작성일 2026-03-27",
        "",
        part("Part A — PHASE 5 구조화 절차 (Auth_Analysis)",
             excerpt("AUTHP5", 1, 372)),
        part("Part B — 인증/인가 분석 방법론 보충 (AUTH_VULN_ANALYSIS)",
             excerpt("AUTH", 1, 7),
             excerpt("AUTH", 20, 36),
             excerpt("AUTH", 40, 166),
             excerpt("AUTH", 249, 353),
             excerpt("AUTH", 387, 436)),
        part("Part C — 익명화 사례 (발견 취약점 목록 + 상세)",
             excerpt("AUTH", 440, 454),
             excerpt("AUTH", 456, 499),
             excerpt("AUTH", 523, 541)),
        part("Part D — 체크리스트 / 최종 판단 요약 / 검색 명령 부록",
             excerpt("AUTH", 598, 610),
             excerpt("AUTH", 627, 639),
             excerpt("AUTH", 641, 712)),
    ])

    files["acl_methodology.md"] = "\n".join([
        "# 접근제어(ACL) 진단 방법론 (ACL 4-1 ~ 4-4 + 사례/체크리스트)",
        "",
        COMMON_NOTE,
        "> task_26 연결: Section B (B-1 ~ B-4), Section E (DAST 후보)",
        "",
        part("Part A — PHASE 4 구조화 절차 (ACL_Analysis)",
             excerpt("ACL", 1, 242)),
        part("Part B — @Acl AOP 구현 분석 보충 (AUTH_VULN_ANALYSIS Step 3)",
             excerpt("AUTH", 168, 247)),
        part("Part C — 익명화 사례 (A-05 ~ A-07)",
             excerpt("AUTH", 543, 596)),
        part("Part D — 접근 제어 체크리스트",
             excerpt("AUTH", 612, 619)),
    ])

    files["race_condition_methodology.md"] = "\n".join([
        "# Race Condition / TOCTOU 진단 방법론 (STEP 1~7, P1~P9)",
        "",
        COMMON_NOTE,
        "> task_26 연결: Section C (C-1 ~ C-8), Section E (DAST 후보)",
        "",
        part("Part A — Race Condition 분석 방법론 (RACE_CONDITION_ANALYSIS)",
             excerpt("RACE", 1, 7),
             excerpt("RACE", 18, 575)),
        part("Part B — 결제/구매 횟수 제한 TOCTOU 보충 (AUTH_VULN_ANALYSIS Step 8)",
             excerpt("AUTH", 355, 385)),
        part("Part C — 익명화 사례 (A-03)",
             excerpt("AUTH", 501, 521)),
        part("Part D — Race Condition 체크리스트 (AUTH_VULN_ANALYSIS)",
             excerpt("AUTH", 621, 625)),
    ])

    files["webview_session_methodology.md"] = "\n".join([
        "# Webview 인증 및 세션 관리 진단 방법론 (Native App ↔ Webview)",
        "",
        COMMON_NOTE,
        "> task_26 연결: Section D (D-1 ~ D-8), Section E (DAST 후보)",
        "> 실행 조건: Auth 5-6에서 Native App + Webview 구조가 확인되었거나, 진단 대상이 모바일 앱/웹뷰 클라이언트 repo인 경우",
        "",
        part("Part A — Webview 인증·세션 분석 방법론 (WEBVIEW_SESSION_ANALYSIS)",
             excerpt("WEBVIEW", 1, 627)),
    ])

    for name, content in files.items():
        (out_dir / name).write_text(content.rstrip() + "\n", encoding="utf-8")
        print(f"[build] {name}: {content.count(chr(10)) + 1} lines")


if __name__ == "__main__":
    build(pathlib.Path(sys.argv[1]))
