"""원본 MD 7개(중복 포함)의 모든 유의미 라인이 고도화 skill 결과물에 존재하는지 기계 검증한다.

검증 규칙
1. 중복 쌍은 md5 동일 여부를 먼저 확인한다 (동일하면 한쪽 검증으로 갈음).
2. 원본 각 라인을 익명화(ANON_MAP) + 정규화(앞뒤 공백, 헤딩 '#' 제거)한 뒤
   결과물(sec-scan-auth/ 이하 모든 .md)의 정규화 라인 집합에 존재하는지 확인한다.
3. 빈 줄, '---', 코드펜스(```), 표 구분선(|---|)은 검증 대상에서 제외한다.
4. 제외 목록은 sec-scan-auth/references/methodology/intentional_exclusions.md 표 A에서 읽고 사유와 함께 보고한다.
   build_methodology.EXCLUDED(생성 시 제외)가 표 A에 모두 있는지도 확인한다 (없으면 FAIL).
5. 결과물에 고객사 식별정보 잔존 여부(FORBIDDEN)를 검사한다.

사용: python -I verify_coverage.py <staging_root>   → 표준출력 + <staging_root>/_review/coverage_report.txt
"""
import hashlib
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from build_methodology import ANON_MAP, EXCLUDED, FORBIDDEN, anonymize  # noqa: E402

ALL_SOURCES = [
    ("AUTH", r"D:\5. Skills\4. AUTH(DAST)_VULN_ANALYSIS.md"),
    ("AUTH", r"D:\5. Skills\MySkills\5. AUTH_VULN_ANALYSIS.md"),
    ("WEBVIEW", r"D:\5. Skills\5. webview-auth-session-analysis.md"),
    ("WEBVIEW", r"D:\5. Skills\MySkills\WEBVIEW_SESSION_ANALYSIS.md"),
    ("ACL", r"D:\5. Skills\MySkills\ACL_Analysis.md"),
    ("AUTHP5", r"D:\5. Skills\MySkills\Auth_Analysis.md"),
    ("RACE", r"D:\5. Skills\MySkills\6. RACE_CONDITION_ANALYSIS.md"),
]


SKIP = re.compile(r"^(-{3,}|`{3}.*|\|?[\s:\-|]+\|?)$")


def norm(line: str) -> str:
    s = line.strip()
    s = re.sub(r"^#{1,6}\s*", "", s)
    return re.sub(r"\s+", " ", s)


def load_exclusions(root: pathlib.Path) -> dict:
    """intentional_exclusions.md 표 A → {원본키: [(시작, 끝, "사유 [결정 ID]"), ...]}"""
    md = root / "sec-scan-auth" / "references" / "methodology" / "intentional_exclusions.md"
    result = {}
    in_a = False
    for line in md.read_text(encoding="utf-8").splitlines():
        if line.startswith("## 표 A"):
            in_a = True
            continue
        if in_a and line.startswith("## "):
            break
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if in_a and len(cols) == 5 and cols[1].isdigit() and cols[2].isdigit():
            result.setdefault(cols[0], []).append((int(cols[1]), int(cols[2]), f"{cols[3]} [{cols[4]}]"))
    return result


def main(root: pathlib.Path):
    out = []
    exclusions = load_exclusions(root)
    builder_gap = [(k, a, b) for k, rows in EXCLUDED.items() for a, b, _ in rows
                   if not any(a == x and b == y for x, y, _ in exclusions.get(k, []))]
    targets = sorted((root / "sec-scan-auth").rglob("*.md"))
    target_set = set()
    corpus = ""
    for t in targets:
        txt = t.read_text(encoding="utf-8")
        corpus += txt
        target_set.update(norm(l) for l in txt.splitlines())

    out.append("# Coverage Verification Report\n")
    out.append("대상 결과물: " + ", ".join(str(t.relative_to(root)) for t in targets) + "\n")

    hashes = {}
    total_checked = total_missing = 0
    verified_keys = set()
    for key, path in ALL_SOURCES:
        data = pathlib.Path(path).read_bytes()
        h = hashlib.md5(data).hexdigest()
        out.append(f"\n## {path}\n- md5: {h}")
        if key in hashes:
            same = hashes[key] == h
            out.append(f"- 중복 쌍 md5 동일: {same}" + (" → 앞선 동일 파일 검증으로 갈음" if same else " → ⚠ 내용 다름, 개별 검증"))
            if same:
                continue
        hashes[key] = h
        lines = data.decode("utf-8").splitlines()
        excl = exclusions.get(key, []) if key not in verified_keys else []
        verified_keys.add(key)
        missing, checked, excluded = [], 0, 0
        for i, raw in enumerate(lines, 1):
            if any(a <= i <= b for a, b, _ in excl):
                if raw.strip():
                    excluded += 1
                continue
            n = norm(anonymize(raw))
            if not n or SKIP.match(n):
                continue
            checked += 1
            if n not in target_set:
                missing.append((i, raw))
        total_checked += checked
        total_missing += len(missing)
        out.append(f"- 검증 라인: {checked} / 누락: {len(missing)} / 제외(사유 기재): {excluded}")
        for a, b, why in excl:
            out.append(f"  - 제외 L{a}-{b}: {why}")
        for i, raw in missing:
            out.append(f"  - ❌ 누락 L{i}: {raw}")

    out.append("\n## 의도적 제외 목록 정합성 (intentional_exclusions.md 표 A)")
    out.append(f"- 표 A 항목: {sum(len(v) for v in exclusions.values())}건")
    for k, a, b in builder_gap:
        out.append(f"  - ❌ 생성기 제외 {k} L{a}-{b}가 표 A에 없음")
    if not builder_gap:
        out.append("- 생성기 제외 목록 ⊆ 표 A ✅")

    out.append("\n## 익명화 잔존 검사")
    hits = [f for f in FORBIDDEN if f in corpus]
    out.append("- 잔존 식별정보: " + (", ".join(hits) if hits else "없음 ✅"))

    out.append(f"\n## 종합\n- 검증 라인 합계: {total_checked}\n- 누락 합계: {total_missing}"
               f"\n- 판정: {'PASS ✅' if total_missing == 0 and not hits and not builder_gap else 'FAIL ❌'}")
    report = "\n".join(out) + "\n"
    (root / "_review" / "coverage_report.txt").write_text(report, encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    print(report)
    sys.exit(0 if total_missing == 0 and not hits and not builder_gap else 1)


if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1]))
