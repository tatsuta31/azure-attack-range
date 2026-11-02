"""Shortlist ESCU detections against the lab attack plan.

Usage: python -I escu_shortlist.py <escu_classified.csv> <out.csv>
Keeps TTP/Anomaly rules in bucket A or C whose ATT&CK technique is in PLAN.
"""
import csv
import sys
from collections import Counter, defaultdict

# technique -> (phase label, how we reproduce it)
PLAN = {
    # credential access
    "T1003.001": ("認証情報", "ART"), "T1003.002": ("認証情報", "ART"),
    "T1003.003": ("認証情報", "ART"), "T1003.006": ("認証情報", "ART(DC)"),
    "T1558.003": ("認証情報", "ART(DC)"), "T1558.004": ("認証情報", "ART(DC)"),
    "T1110.001": ("認証情報", "手動"), "T1110.003": ("認証情報", "ART/手動"),
    "T1552.001": ("認証情報", "ART"),
    # discovery
    "T1087.001": ("偵察", "ART/Caldera"), "T1087.002": ("偵察", "ART/Caldera"),
    "T1069.001": ("偵察", "ART"), "T1069.002": ("偵察", "ART"),
    "T1482": ("偵察", "ART/Caldera"), "T1018": ("偵察", "ART"),
    "T1016": ("偵察", "ART/Caldera"), "T1033": ("偵察", "Caldera"),
    "T1057": ("偵察", "Caldera"), "T1135": ("偵察", "Caldera"),
    "T1518.001": ("偵察", "Caldera"), "T1615": ("偵察", "Caldera"),
    "T1046": ("偵察", "ART/手動"),
    # execution / evasion
    "T1059.001": ("実行", "ART/Caldera"), "T1059.003": ("実行", "ART"),
    "T1027": ("回避", "Caldera(base64)"), "T1036.005": ("回避", "Caldera"),
    "T1562.001": ("回避", "ART"), "T1070.001": ("回避", "ART"),
    "T1218.011": ("回避", "ART"), "T1218.005": ("回避", "ART"),
    # persistence / privilege
    "T1053.005": ("永続化", "ART/Caldera"), "T1543.003": ("永続化", "ART"),
    "T1547.001": ("永続化", "ART"), "T1136.001": ("永続化", "ART/手動"),
    "T1136.002": ("永続化", "ART(DC)"), "T1098": ("永続化", "ART(DC)"),
    # lateral movement
    "T1021.001": ("横展開", "手動(RDP)"), "T1021.002": ("横展開", "ART"),
    "T1021.006": ("横展開", "ART"), "T1047": ("横展開", "ART"),
    "T1570": ("横展開", "ART"),
    # linux
    "T1053.003": ("Linux", "ART"), "T1548.003": ("Linux", "ART"),
    "T1070.003": ("Linux", "ART"), "T1222.002": ("Linux", "ART"),
    "T1105": ("C2/持ち込み", "ART"),
}


def main(src, out):
    keep = []
    with open(src, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["bucket"] not in ("A", "C") or r["type"] not in ("TTP", "Anomaly"):
                continue
            techs = [t for t in r["mitre"].split(",") if t in PLAN]
            if not techs:
                continue
            phase, how = PLAN[techs[0]]
            r.update({"phase": phase, "reproduce": how, "plan_techniques": ",".join(techs)})
            keep.append(r)
    keep.sort(key=lambda r: (r["phase"], r["plan_techniques"], r["type"], r["name"]))
    with open(out, "w", newline="", encoding="utf-8") as f:
        cols = ["phase", "plan_techniques", "name", "type", "platform", "bucket",
                "reproduce", "data_source", "mitre"]
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(keep)
    print("shortlist:", len(keep))
    print(sorted(Counter(r["phase"] for r in keep).items()))
    per = defaultdict(int)
    for r in keep:
        per[r["plan_techniques"].split(",")[0]] += 1
    print(sorted(per.items(), key=lambda x: -x[1]))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
