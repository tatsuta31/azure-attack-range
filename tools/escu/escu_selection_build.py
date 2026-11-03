"""Build docs/escu/escu_selection.csv and the rule tables in docs/escu-selection.md.

Usage:
  python -I escu_selection_build.py <savedsearches.conf> <art_index_dir>

- The rule list (section, rule, mitre, reproduce) comes from docs/escu/escu_selection.csv.
  Edit that file to add or remove rules, then rerun this script.
- Stories, type and data sources come from the ESCU package (savedsearches.conf).
- Summary, ART tests, SPL fixes and memo come from selection_notes.py.
- ART test names come from the ART index CSVs (windows-index.csv / linux-index.csv in
  <art_index_dir>), downloaded from
  https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/Indexes/Indexes-CSV
The tables in the Markdown file are replaced between the BEGIN/END markers.
"""
import csv
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
from escu_extract import parse_conf  # noqa: E402
from selection_notes import COMMON_FIXES, NOTES  # noqa: E402

CSV_PATH = os.path.join(ROOT, "docs", "escu", "escu_selection.csv")
MD_PATH = os.path.join(ROOT, "docs", "escu-selection.md")
BEGIN, END = "<!-- BEGIN RULE TABLES (generated) -->", "<!-- END RULE TABLES (generated) -->"
FIELDS = ["section", "rule", "saved_search", "type", "mitre", "analytic_stories", "summary_ja",
          "reproduce", "art_tests", "data_source", "spl_fix", "memo"]


def art_names(art_dir):
    names = {}
    for plat in ("windows", "linux"):
        with open(os.path.join(art_dir, f"{plat}-index.csv"), encoding="utf-8") as f:
            for r in csv.DictReader(f):
                names[(plat, r["Technique #"], r["Test #"])] = r["Test Name"]
    return names


def expand_art(spec, plat, names):
    """'T1003.001 #1, #4' -> 'T1003.001 #1 (name); T1003.001 #4 (name)'."""
    out, tech = [], None
    for tok in [t.strip() for t in spec.split(",") if t.strip()]:
        m = re.match(r"(T[\d.]+)?\s*#(\d+)$", tok)
        if not m:
            raise SystemExit(f"bad ART reference: {tok}")
        tech = m.group(1) or tech
        name = names.get((plat, tech, m.group(2)))
        if name is None:
            raise SystemExit(f"ART test not found: {plat} {tech} #{m.group(2)}")
        out.append(f"{tech} #{m.group(2)}（{name}）")
    return "; ".join(out)


def expand_fix(key):
    if not key:
        return ""
    return "; ".join(f"[{k}] {COMMON_FIXES[k]}" if k in COMMON_FIXES else k for k in key.split(","))


def cell(s):
    return s.replace("|", "\\|").replace("\n", " ")


def main(conf_path, art_dir):
    conf = parse_conf(conf_path)
    names = art_names(art_dir)
    with open(CSV_PATH, encoding="utf-8-sig") as f:
        base = list(csv.DictReader(f))
    rows = []
    for b in base:
        stanza = f"ESCU - {b['rule']} - Rule"
        if stanza not in conf:
            raise SystemExit(f"rule not in this ESCU package: {b['rule']}")
        ann = json.loads(conf[stanza].get("action.correlationsearch.annotations", "{}") or "{}")
        summary, art, fix, memo = NOTES[b["rule"]]
        plat = "linux" if b["rule"].startswith("Linux") else "windows"
        rows.append({
            "section": b["section"], "rule": b["rule"], "saved_search": stanza,
            "type": ann.get("type", ""), "mitre": b["mitre"],
            "analytic_stories": " / ".join(ann.get("analytic_story", [])),
            "summary_ja": summary, "reproduce": b["reproduce"],
            "art_tests": expand_art(art, plat, names) if art else "",
            "data_source": " / ".join(ann.get("data_source", [])),
            "spl_fix": fix, "memo": memo,
        })
    # CSV keeps the short fix keys readable for Excel users too: expand them.
    with open(CSV_PATH, "w", encoding="utf-8-sig", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=FIELDS)
        wr.writeheader()
        for r in rows:
            wr.writerow({**r, "spl_fix": expand_fix(r["spl_fix"])})

    lines, section = [], None
    for r in rows:
        if r["section"] != section:
            section = r["section"]
            lines += ["", f"### {section}", "",
                      "| ルール | ATT&CK | 種別 | ESCU ストーリー | 概要 | 再現方法 | ART のテスト | SPL・マクロの修正 | メモ |",
                      "|---|---|---|---|---|---|---|---|---|"]
        lines.append("| " + " | ".join(cell(x) for x in [
            r["rule"], r["mitre"], r["type"], r["analytic_stories"], r["summary_ja"], r["reproduce"],
            r["art_tests"] or "—", r["spl_fix"].replace(",", ", ") or "—", r["memo"] or ""]) + " |")
    md = open(MD_PATH, encoding="utf-8").read()
    if BEGIN not in md or END not in md:
        raise SystemExit("markers not found in " + MD_PATH)
    head, rest = md.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    with open(MD_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write(head + BEGIN + "\n" + "\n".join(lines).lstrip("\n") + "\n\n" + END + tail)
    print(f"{len(rows)} rules -> {CSV_PATH}, {MD_PATH}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2])
