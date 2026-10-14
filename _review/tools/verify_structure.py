"""v2 모듈 구조의 내부 정합성을 기계 검증한다 (verify_coverage.py 보완).

검증 항목
S1. 파일 존재        — SKILL/commands/task_26/dast_candidates/m0~m5/methodology 4종
S2. 경로 참조        — 결과물 안의 `references/...`, `shared/...` 경로가 실제로 존재하는지
S3. 모듈 헤더        — m1~m5 상단에 실행 조건 / Auto-Scan 연결 / finding category / ID 접두어가 있는지
S4. category·ID      — 모듈의 category가 taxonomy Section 6의 9종 안인지, ID 접두어가 task_26 ID 규칙 안인지
S5. 판정 문구        — `**CATEGORY, 취약|정보, Severity**` 형식의 category/severity가 허용값인지
S6. 교차 참조        — 본문의 "M2 A-5", "M4 D-9" 같은 모듈·절 참조가 실제 헤딩으로 존재하는지
S7. --skip 값        — SKILL/M0에 적힌 --skip 값이 스크립트 argparse choices 안인지
S8. summary 섹션     — 모듈·task_26이 가리키는 summary_auth.md 「섹션」이 SKILL.md 템플릿에 있는지
S9. 출력 스키마      — task_26 예시 finding + v2 추가 필드로 만든 샘플이 validate_findings.py를 통과하는지
S10. v1 대비 변경    — v1 원본(SKILL/task_26/commands) 라인 중 v2에 없는 라인 목록 (정보성, 판정에 미반영)
S11. 식별정보 잔존   — staging 전체 (.claude/commands 포함)

사용: py -3 -I verify_structure.py <staging_root> <palantir_repo_root>
      → 표준출력 + <staging_root>/_review/structure_report.txt
"""
import json
import pathlib
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from verify_coverage import FORBIDDEN, SKIP, norm  # noqa: E402

CATEGORIES = {"IDOR", "PRIVILEGE_ESCALATION", "AUTH_BYPASS", "PIN_REVERIFICATION_MISSING",
              "SESSION_TOKEN_EXPOSURE", "BROKEN_ACCESS_CONTROL", "IP_ACL_BYPASS",
              "INTERNAL_API_EXPOSURE", "RACE_CONDITION"}
SEVERITIES = {"Critical", "High", "Medium", "Low", "Info", "Informational", "Medium~High"}
MODULES = ["m0_auth_recon", "m1_authn", "m2_authz_acl", "m3_stepup_mfa", "m4_logic_race", "m5_webview_client"]
SECTION_PREFIX = {"M0": "R", "M1": "A", "M2": "AB", "M3": "C", "M4": "D", "M5": "E"}


class Report:
    def __init__(self):
        self.lines, self.fail = [], 0

    def h(self, title):
        self.lines.append(f"\n## {title}")

    def ok(self, msg):
        self.lines.append(f"- ✅ {msg}")

    def bad(self, msg):
        self.fail += 1
        self.lines.append(f"- ❌ {msg}")

    def info(self, msg):
        self.lines.append(f"- {msg}")


def read(p):
    return p.read_text(encoding="utf-8")


def main(stage: pathlib.Path, repo: pathlib.Path):
    r = Report()
    skill_dir = stage / "sec-scan-auth"
    ref = skill_dir / "references"
    files = {
        "SKILL.md": skill_dir / "SKILL.md",
        "commands": stage / ".claude" / "commands" / "sec-scan-auth.md",
        "task_26": ref / "task_prompts" / "task_26_auth_review.md",
        "dast_candidates": ref / "dast_candidates.md",
        **{m: ref / "modules" / f"{m}.md" for m in MODULES},
        **{m: ref / "methodology" / f"{m}.md" for m in
           ["auth_methodology", "acl_methodology", "race_condition_methodology", "webview_session_methodology"]},
    }

    # S1
    r.h("S1. 파일 존재")
    for k, p in files.items():
        (r.ok if p.exists() else r.bad)(f"{k}: {p.relative_to(stage)}")
    texts = {k: read(p) for k, p in files.items() if p.exists()}
    live = {k: v for k, v in texts.items() if "methodology" not in k}  # 원문 보존본은 참조 검사 대상 아님

    # S2
    r.h("S2. 경로 참조")
    path_re = re.compile(r"`((?:references|shared|sec-scan-[a-z]+)/[A-Za-z0-9_./*-]+\.(?:md|py|json))`")
    seen = set()
    for k, t in live.items():
        for m in path_re.finditer(t):
            rel = m.group(1)
            if "*" in rel or rel in seen:
                continue
            seen.add(rel)
            target = (skill_dir / rel if rel.startswith("references/")
                      else stage / rel if rel.startswith("sec-scan-auth/")   # v2 결과물은 staging 기준
                      else repo / rel)
            (r.ok if target.exists() else r.bad)(f"{rel}  (첫 참조: {k})")

    # S3 / S4
    r.h("S3. 모듈 헤더 · S4. category / ID 접두어")
    id_rule = set(re.findall(r"`(AUTH-[A-Z]+)-NNN`", texts.get("task_26", "")))
    for m in MODULES[1:]:
        head = texts.get(m, "").split("---", 1)[0]
        for key in ["**실행 조건**", "**Auto-Scan 연결**", "**finding category**", "**ID 접두어"]:
            (r.ok if key in head else r.bad)(f"{m}: {key.strip('*')}")
        cat_line = next((l for l in head.splitlines() if l.startswith("**finding category**")), "")
        for c in re.findall(r"`([A-Z_]+)`", cat_line):
            (r.ok if c in CATEGORIES else r.bad)(f"{m}: category {c}")
        id_line = next((l for l in head.splitlines() if l.startswith("**ID 접두어")), "")
        for pid in re.findall(r"`(AUTH-[A-Z]+)-NNN`", id_line):
            (r.ok if pid in id_rule else r.bad)(f"{m}: ID 접두어 {pid} ∈ task_26 ID 규칙")

    # S5
    r.h("S5. 판정 문구 category / severity")
    verdict_re = re.compile(r"\*\*([A-Z_]+)(?:\([^)]*\))?, (취약|정보)(?:, ([^*]+))?\*\*")
    n = 0
    for k, t in live.items():
        for m in verdict_re.finditer(t):
            n += 1
            cat, sev = m.group(1), (m.group(3) or "").strip()
            if cat not in CATEGORIES:
                r.bad(f"{k}: 허용되지 않은 category '{cat}' — {m.group(0)}")
            sev_head = re.split(r"\s|\(", sev)[0] if sev else ""
            if sev and sev_head not in SEVERITIES:
                r.bad(f"{k}: 허용되지 않은 severity '{sev}' — {m.group(0)}")
    r.info(f"판정 문구 {n}건 검사")
    if r.fail == 0:
        r.ok("전건 허용값")

    # S6
    r.h("S6. 모듈·절 교차 참조")
    headings = {}
    for i, m in enumerate(MODULES):
        mod = f"M{i}"
        headings[mod] = set(re.findall(r"^### ([A-Z]-\d+)\.", texts.get(m, ""), re.M))
    ref_re = re.compile(r"\b(M[0-5]) ([A-Z]-\d+)(?:\s*~\s*([A-Z]-\d+))?")
    bad_refs = set()
    total = 0
    for k, t in live.items():
        for m in ref_re.finditer(t):
            mod, a, b = m.group(1), m.group(2), m.group(3)
            for sec in filter(None, [a, b]):
                total += 1
                if sec not in headings[mod]:
                    bad_refs.add(f"{k}: {mod} {sec}")
    for b in sorted(bad_refs):
        r.bad(f"존재하지 않는 절 참조 — {b}")
    r.info(f"참조 {total}건 검사, 오류 {len(bad_refs)}건")
    for mod, hs in headings.items():
        r.info(f"{mod} 헤딩: {', '.join(sorted(hs))}")

    # S7
    r.h("S7. --skip 값")
    script = read(repo / "shared" / "scripts" / "scan_auth_access_control.py")
    cm = re.search(r'"--skip".*?choices=\[(.*?)\]', script, re.S)
    choices = set(re.findall(r'"(\w+)"', cm.group(1))) if cm else set()
    r.info(f"스크립트 choices: {sorted(choices)}")
    used = set()
    for k in ["SKILL.md", "task_26", "m0_auth_recon"] + MODULES[1:]:
        t = texts.get(k, "")
        used |= set(re.findall(r"--skip (\w+)", t))                 # `--skip pin`, `(--skip idor)`
        for grp in re.findall(r"M\d: `([a-z ]+)`", t):              # M0: `M1: \`session testbypass\``
            used |= set(grp.split())
    in_table = False
    for line in texts.get("SKILL.md", "").splitlines():            # SKILL.md 모듈 ↔ --skip 매핑 표 2열
        if line.startswith("| 모듈 | `--skip` 값"):
            in_table = True
            continue
        if in_table and not line.startswith("|"):
            break
        if in_table and line.startswith("| M"):
            used |= set(re.findall(r"`(\w+)`", line.split("|")[2]))
    used = {u for u in used if u.islower()}
    for u in sorted(used):
        (r.ok if u in choices else r.bad)(f"--skip {u}")

    # S8
    r.h("S8. summary_auth.md 섹션")
    skill_sections = set(re.findall(r"^## (.+)$", texts.get("SKILL.md", ""), re.M))
    wanted = set()
    for k, t in live.items():
        wanted |= set(re.findall(r"「([^」]+)」", t))
    summary_like = {w for w in wanted if w in {"인증 아키텍처 요약", "모듈별 판정 요약", "2차 인증·문자 인증 코드 신호", "동적 확인 후보"}}
    for w in sorted(summary_like):
        hit = any(s.startswith(w) for s in skill_sections)
        (r.ok if hit else r.bad)(f"「{w}」 ∈ SKILL.md summary 템플릿")
    for w in sorted(wanted - summary_like):
        r.info(f"(summary 외 참조) 「{w}」")

    # S9 — validate_findings.py는 현재 auth(AUTH-/category 9종)를 허용 목록에 두지 않는다 (v1부터의 공유 스크립트 갭).
    #      그래서 v1 형태 샘플과 v2 형태 샘플의 오류 목록을 비교해 "v2 추가 필드가 새 오류를 만들지 않는가"를 판정한다.
    r.h("S9. 출력 스키마 — validate_findings.py (v1 대비 신규 오류 여부)")
    v2_sample = {
        "task_id": "auth",
        "findings": [{
            "finding_id": "AUTH-001", "title": "IDOR — 샘플", "severity": "High", "risk_level": 4,
            "category": "IDOR", "cwe_id": "CWE-639", "owasp_category": "A01:2021 Broken Access Control",
            "result": "취약", "diagnosis_method": "교차검증(수동)", "source": "llm-check",
            "source_module": "M2", "verification_status": "code-confirmed",
            "fn_detected": False, "fp_corrected": False,
            "scope": {"type": "endpoint", "endpoint": "/api/v1/order/cancel", "file": "a/B.kt", "line": 1, "module": None},
            "description": "샘플", "recommendation": "샘플",
            "evidence": {"file": "a/B.kt", "line": 1, "code_snippet": "x"}, "needs_review": False,
        }],
        "summary": {"total": 1, "취약": 1, "정보": 0, "fn_detected": 0, "needs_dynamic_verification": 0},
        "llm_checked": True, "evidence_trail": [],
    }
    v1_sample = json.loads(json.dumps(v2_sample))
    for k in ("source_module", "verification_status"):
        v1_sample["findings"][0].pop(k)
    v1_sample["summary"].pop("needs_dynamic_verification")

    def run_validator(sample):
        with tempfile.TemporaryDirectory() as td:
            sp = pathlib.Path(td) / "findings_AUTH.json"
            sp.write_text(json.dumps(sample, ensure_ascii=False), encoding="utf-8")
            # -I는 PYTHONIOENCODING을 무시하므로 -X utf8로 출력 인코딩(cp949 콘솔 대응) 고정
            res = subprocess.run([sys.executable, "-I", "-X", "utf8",
                                  str(repo / "shared" / "scripts" / "validate_findings.py"), str(sp)],
                                 capture_output=True, text=True, encoding="utf-8", errors="replace")
            errs = {l.strip() for l in res.stdout.splitlines() if l.strip().startswith("[findings")}
            return res.returncode, errs, res.stderr.strip()

    rc1, e1, se1 = run_validator(v1_sample)
    rc2, e2, se2 = run_validator(v2_sample)
    if se1 or se2:
        r.bad(f"validator 실행 오류 — {(se1 or se2)[-300:]}")
    r.info(f"v1 형태 샘플: exit={rc1}, 오류 {len(e1)}건")
    for e in sorted(e1):
        r.info(f"  (기존 갭) {e}")
    new = e2 - e1
    if new:
        for e in sorted(new):
            r.bad(f"v2 추가 필드로 인한 신규 오류 — {e}")
    else:
        r.ok(f"v2 형태 샘플: 신규 오류 0건 (source_module / verification_status / summary.needs_dynamic_verification 허용)")

    # S10
    r.h("S10. v1 대비 v2에서 사라진 라인 (정보성 — CHANGES 검토용)")
    v2_set = set()
    for p in list(skill_dir.rglob("*.md")) + [files["commands"]]:
        v2_set.update(norm(l) for l in read(p).splitlines())
    orig = stage / "_review" / "original"
    for name in ["SKILL.md", "task_26_auth_review.md", "command_sec-scan-auth.md"]:
        p = orig / name
        if not p.exists():
            r.bad(f"원본 백업 없음: {name}")
            continue
        gone = []
        for i, raw in enumerate(read(p).splitlines(), 1):
            nl = norm(raw)
            if nl and not SKIP.match(nl) and nl not in v2_set:
                gone.append((i, raw.strip()))
        r.info(f"**{name}**: v2에 없는 라인 {len(gone)}건")
        for i, s in gone:
            r.info(f"  L{i}: {s[:160]}")

    # S11
    r.h("S11. 식별정보 잔존 (staging 전체)")
    hits = []
    for p in list(skill_dir.rglob("*.md")) + [files["commands"]]:
        t = read(p)
        hits += [f"{p.relative_to(stage)}: {f}" for f in FORBIDDEN if f in t]
    if hits:
        for h in hits:
            r.bad(h)
    else:
        r.ok("없음")

    r.lines.insert(0, "# Structure Verification Report")
    r.lines.append(f"\n## 종합\n- 오류: {r.fail}\n- 판정: {'PASS ✅' if r.fail == 0 else 'FAIL ❌'}")
    report = "\n".join(r.lines) + "\n"
    (stage / "_review" / "structure_report.txt").write_text(report, encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    print(report)
    sys.exit(0 if r.fail == 0 else 1)


if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
