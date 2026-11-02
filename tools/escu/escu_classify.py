"""Classify ESCU detections for the azure-attack-range lab.

Usage: python -I escu_classify.py <escu.csv> <art_windows.csv> <art_linux.csv> <out.csv>

availability (per data source alternative; a rule takes its best alternative):
  ok      : collected in the lab as built (advanced_logging: "1" on Windows)
  config  : Windows log that needs an extra audit policy / channel to be collected
  palo    : Palo Alto logs (needs the planned VM-Series)
  no      : product not in the lab
bucket:
  A  : available (ok) and Atomic Red Team has a test for one of its techniques
  B  : network detection fed by Palo Alto
  C  : available (ok) but no ART test -> reproduce by hand over RDP/SSH
  -  : not reproducible in the lab
"""
import csv
import re
import sys

# Security event IDs produced with advanced_logging (auditpol subcategories in
# windows_common/tasks/advanced_logging.yml) plus defaults.
SEC_OK = {
    "1102", "4624", "4625", "4634", "4647", "4648", "4656", "4657", "4658", "4660",
    "4661", "4662", "4663", "4672", "4673", "4674", "4688", "4689", "4697", "4698",
    "4699", "4700", "4701", "4702", "4703", "4719", "4720", "4722", "4723", "4724",
    "4725", "4726", "4727", "4728", "4729", "4730", "4731", "4732", "4733", "4734",
    "4735", "4737", "4738", "4740", "4741", "4742", "4743", "4754", "4755", "4756",
    "4757", "4758", "4764", "4765", "4766", "4767", "4768", "4769", "4770", "4771",
    "4772", "4776", "4778", "4779", "4781", "4798", "4799", "5140", "5142", "5143",
    "5144", "5145", "5156", "5157", "4616", "4608", "4964",
}
RANK = {"ok": 3, "palo": 2, "config": 1, "no": 0}


def source_status(src):
    s = src.strip()
    if s.startswith("Sysmon for Linux") or s.startswith("Linux Auditd") or s == "osquery":
        return "ok", "linux"
    if s.startswith("Sysmon EventID"):
        return "ok", "windows"
    m = re.match(r"Windows Event Log Security (\d+)", s)
    if m:
        return ("ok" if m.group(1) in SEC_OK else "config"), "windows"
    if s.startswith("Windows Event Log System") or s.startswith("Windows Event Log Application"):
        return "ok", "windows"
    if s.startswith("Powershell Script Block Logging"):
        return "ok", "windows"
    if s.startswith("Windows Event Log") or s.startswith("NTLM Operational") \
            or s.startswith("Windows ") or s.startswith("Powershell"):
        return "config", "windows"
    if s.startswith("Palo Alto"):
        return "palo", "network"
    return "no", ""


def alt_status(alt):
    # "A AND B" needs every part
    parts = [source_status(p) for p in alt.split(" AND ")]
    status = min((p[0] for p in parts), key=lambda x: RANK[x])
    platform = next((p[1] for p in parts if p[1]), "")
    return status, platform


def load_art(path):
    techs = set()
    with open(path, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            techs.add(r["Technique #"].strip())
    return techs


def art_hit(mitre, art):
    hits = []
    for t in filter(None, mitre.split(",")):
        if t in art or any(a.startswith(t + ".") for a in art):
            hits.append(t)
    return hits


def main(escu_csv, art_win, art_lin, out):
    art = {"windows": load_art(art_win), "linux": load_art(art_lin)}
    rows = []
    with open(escu_csv, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["deprecated"] == "1":
                continue
            alts = [a for a in r["data_source"].split(" | ") if a]
            best, platform = "no", ""
            for a in alts:
                st, pf = alt_status(a)
                if RANK[st] > RANK[best]:
                    best, platform = st, pf
            hits = art_hit(r["mitre"], art.get(platform, set())) if best == "ok" else []
            if best == "palo":
                bucket = "B"
            elif best == "ok" and hits:
                bucket = "A"
            elif best == "ok":
                bucket = "C"
            else:
                bucket = "-"
            r.update({"availability": best, "platform": platform,
                      "art_techniques": ",".join(hits), "bucket": bucket})
            rows.append(r)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    from collections import Counter
    print("availability:", Counter(r["availability"] for r in rows).most_common())
    print("bucket x platform:", sorted(Counter((r["bucket"], r["platform"]) for r in rows).items()))
    print("bucket x type:", sorted(Counter((r["bucket"], r["type"]) for r in rows if r["bucket"] != "-").items()))


if __name__ == "__main__":
    main(*sys.argv[1:5])
