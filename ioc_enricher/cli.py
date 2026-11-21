import argparse
import os
import sys

from .cache import Cache
from .clients import MIN_INTERVAL, VirusTotalClient
from .enricher import enrich
from .parser import parse_iocs
from .report import format_table, write_csv, write_markdown
from .scoring import add_verdicts


def build_parser():
    p = argparse.ArgumentParser(
        prog="ioc_enricher",
        description="Enrich a list of IOCs with VirusTotal and produce a verdict report. "
                    "It only queries; it never uploads files or URLs.",
    )
    p.add_argument(
        "input", help="IOC list, one indicator per line. Use '-' for standard input")
    p.add_argument("--out-dir", default="reports",
                   help="report directory (default: reports)")
    p.add_argument("--formats", nargs="+", choices=["csv", "md"], default=["csv", "md"],
                   help="report formats to write (default: csv md)")
    p.add_argument("--cache-file", default="cache.json",
                   help="cache file path")
    p.add_argument("--ttl-hours", type=float, default=24,
                   help="cache lifetime in hours")
    p.add_argument("--refresh", action="store_true",
                   help="ignore the cache and query everything again")
    p.add_argument("--max-queries", type=int, default=100,
                   help="maximum API queries allowed in one run (default: 100)")
    p.add_argument("--dry-run", action="store_true",
                   help="show the plan without calling the API")
    return p


def read_lines(path):
    if path == "-":
        return sys.stdin.read().splitlines()
    with open(path, encoding="utf-8") as f:
        return f.read().splitlines()


def main(argv=None, client_factory=VirusTotalClient, out=None, err=None):
    out = out or sys.stdout
    err = err or sys.stderr
    args = build_parser().parse_args(argv)

    try:
        lines = read_lines(args.input)
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Could not read input: {exc}", file=err)
        return 2

    accepted, skipped = parse_iocs(lines)
    if not accepted:
        print("No valid indicators to look up.", file=err)
        return 2

    ttl = 0 if args.refresh else args.ttl_hours * 3600
    cache = Cache(args.cache_file, ttl=ttl)
    pending = [i for i in accepted if cache.get(i["kind"], i["value"]) is None]
    eta = int(len(pending) * MIN_INTERVAL)
    print(
        f"{len(accepted)} indicators, {len(accepted) - len(pending)} cached, "
        f"{len(pending)} API queries (~{eta} s); {len(skipped)} inputs skipped.",
        file=err,
    )

    if args.dry_run:
        return 0
    if len(pending) > args.max_queries:
        print(f"Planned query count ({len(pending)}) exceeds the --max-queries limit"
              f"({args.max_queries}) Shrink the list or raise the limit deliberately.",
              file=err)
        return 2

    try:
        client = client_factory()
    except RuntimeError as exc:
        print(exc, file=err)
        return 2

    try:
        results = add_verdicts(enrich(accepted, client, cache))
    except KeyboardInterrupt:
        print("\nCancelled. Completed lookups are cached; rerun to resume.",
              file=err)
        return 130

    print(format_table(results), file=out)

    os.makedirs(args.out_dir, exist_ok=True)
    written = []
    if "csv" in args.formats:
        path = os.path.join(args.out_dir, "report.csv")
        write_csv(results, path)
        written.append(path)
    if "md" in args.formats:
        path = os.path.join(args.out_dir, "report.md")
        write_markdown(results, path, skipped)
        written.append(path)
    print("\nReport written: " + ", ".join(written), file=err)
    return 0
