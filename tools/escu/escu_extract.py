"""Extract ESCU detections from savedsearches.conf into a CSV.

Usage: python -I escu_extract.py <savedsearches.conf> <out.csv>
Only detections (action.escu.search_type = detection) are kept.
"""
import csv
import json
import sys


def parse_conf(path):
    stanzas, name, cur, last_key = {}, None, {}, None
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if line.startswith("[") and line.endswith("]"):
                if name:
                    stanzas[name] = cur
                name, cur, last_key = line[1:-1], {}, None
                continue
            if name is None:
                continue
            # continuation lines end with a backslash in .conf files
            if last_key and cur.get(last_key, "").endswith("\\"):
                cur[last_key] = cur[last_key][:-1] + "\n" + line
                continue
            if " = " in line:
                k, v = line.split(" = ", 1)
                cur[k.strip()] = v
                last_key = k.strip()
    if name:
        stanzas[name] = cur
    return stanzas


def load_json(s, default):
    try:
        return json.loads(s)
    except Exception:
        return default


def main(conf, out):
    rows = []
    for name, kv in parse_conf(conf).items():
        if not name.startswith("ESCU - "):
            continue
        if kv.get("action.escu.search_type") != "detection":
            continue
        ann = load_json(kv.get("action.correlationsearch.annotations", "{}"), {})
        meta = load_json(kv.get("action.correlationsearch.metadata", "{}"), {})
        search = kv.get("search", "")
        rows.append({
            "name": name[len("ESCU - "):].removesuffix(" - Rule"),
            "type": ann.get("type", ""),
            "mitre": ",".join(ann.get("mitre_attack", [])),
            "data_source": " | ".join(ann.get("data_source", [])),
            "deprecated": meta.get("deprecated", ""),
            "uses_tstats": "1" if "tstats" in search else "0",
            "analytic_story": " | ".join(ann.get("analytic_story", [])),
            "security_domain": kv.get("action.notable.param.security_domain", ""),
        })
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"detections: {len(rows)}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
