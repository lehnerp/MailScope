"""Analyse emails from the command line (no server needed).

    python cli.py suspicious.eml other.msg          # summary table
    python cli.py suspicious.eml --json > out.json  # full report
"""
import argparse
import json
import sys

from analyzer import analyze


def main():
    ap = argparse.ArgumentParser(description="MailScope EML/MSG analyser")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--json", action="store_true", help="print full JSON report(s)")
    ap.add_argument("--rdns", action="store_true", help="live reverse DNS on origin IP")
    a = ap.parse_args()
    reports = []
    for path in a.files:
        with open(path, "rb") as fh:
            rep = analyze(fh.read(), path.replace("\\", "/").split("/")[-1], rdns=a.rdns)
        reports.append(rep)
        if not a.json:
            s, o = rep["scoring"], rep["trace"].get("origin") or {}
            print(f"\n{s['score']:>3}/100  {s['verdict']:<28} {path}")
            print(f"        subject: {rep['summary']['subject']}")
            print(f"        from:    {rep['summary']['from']}   origin: {o.get('ip', '-')}")
            for f in s["findings"]:
                if f["weight"]:
                    print(f"        {f['weight']:+4}  {f['title']}")
    if a.json:
        for r in reports:
            r["body"].pop("html", None)
        json.dump(reports if len(reports) > 1 else reports[0], sys.stdout, indent=2, ensure_ascii=False)
    worst = max(r["scoring"]["score"] for r in reports)
    sys.exit(2 if worst >= 45 else 1 if worst >= 20 else 0)  # handy for scripts


if __name__ == "__main__":
    main()
