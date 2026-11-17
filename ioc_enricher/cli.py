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
        description="IOC listesini VirusTotal ile zenginleştirir ve karar raporu üretir. "
                    "Yalnızca sorgu yapar; dosya ya da URL göndermez.",
    )
    p.add_argument(
        "input", help="IOC listesi (her satırda bir gösterge). Standart girdi için '-'")
    p.add_argument("--out-dir", default="reports",
                   help="rapor klasörü (varsayılan: reports)")
    p.add_argument("--formats", nargs="+", choices=["csv", "md"], default=["csv", "md"],
                   help="üretilecek rapor biçimleri (varsayılan: csv md)")
    p.add_argument("--cache-file", default="cache.json",
                   help="önbellek dosyası")
    p.add_argument("--ttl-hours", type=float, default=24,
                   help="önbellek geçerlilik süresi (saat)")
    p.add_argument("--refresh", action="store_true",
                   help="önbelleği yok say, hepsini yeniden sorgula")
    p.add_argument("--max-queries", type=int, default=100,
                   help="bir çalıştırmada izin verilen en fazla API sorgusu (varsayılan: 100)")
    p.add_argument("--dry-run", action="store_true",
                   help="API'ye gitmeden planı göster")
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
        print(f"Girdi okunamadı: {exc}", file=err)
        return 2

    accepted, skipped = parse_iocs(lines)
    if not accepted:
        print("Sorgulanacak geçerli gösterge yok.", file=err)
        return 2

    ttl = 0 if args.refresh else args.ttl_hours * 3600
    cache = Cache(args.cache_file, ttl=ttl)
    pending = [i for i in accepted if cache.get(i["kind"], i["value"]) is None]
    eta = int(len(pending) * MIN_INTERVAL)
    print(
        f"{len(accepted)} gösterge, {len(accepted) - len(pending)} önbellekte, "
        f"{len(pending)} API sorgusu (~{eta} sn); {len(skipped)} girdi atlandı.",
        file=err,
    )

    if args.dry_run:
        return 0
    if len(pending) > args.max_queries:
        print(f"Planlanan sorgu sayısı ({len(pending)}) --max-queries sınırını "
              f"({args.max_queries}) aşıyor. Listeyi küçült ya da sınırı bilinçli olarak yükselt.",
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
        print("\nİptal edildi. Tamamlanan sorgular önbellekte, yeniden çalıştırınca devam eder.",
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
    print("\nRapor yazıldı: " + ", ".join(written), file=err)
    return 0
