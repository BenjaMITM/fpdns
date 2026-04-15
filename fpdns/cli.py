"""fpdns command-line interface."""

import sys
import argparse
import concurrent.futures

from .fingerprint import DNSFingerprint
from .utils import resolve_to_ips, get_ns_ips


def _process_target(engine, target, port, short, separator, domain_mode):
    """Resolve *target* and fingerprint each resulting address.

    Returns a list of output lines (never raises).
    """
    lines = []
    try:
        if domain_mode:
            ns_pairs = get_ns_ips(target, use_tcp=engine.forcetcp,
                                  source=engine.source)
            if not ns_pairs:
                print(f"no nameservers found for {target}", file=sys.stderr)
                return lines
            for ns_name, addr in ns_pairs:
                fp = engine.string(addr, port)
                if short:
                    lines.append(f"{addr:<15}{separator}{fp}")
                else:
                    lines.append(
                        f"fingerprint ({target} via {ns_name}, {addr}): {fp}"
                    )
        else:
            addresses = resolve_to_ips(target, use_tcp=engine.forcetcp,
                                       source=engine.source)
            if not addresses:
                print(f"host not found ({target})", file=sys.stderr)
                return lines
            for addr in addresses:
                fp = engine.string(addr, port)
                if short:
                    lines.append(f"{addr:<15}{separator}{fp}")
                else:
                    if addr == target:
                        lines.append(f"fingerprint ({addr}): {fp}")
                    else:
                        lines.append(f"fingerprint ({target}, {addr}): {fp}")
    except Exception as exc:
        print(f"error processing {target}: {exc}", file=sys.stderr)

    return lines


def main():
    parser = argparse.ArgumentParser(
        prog="fpdns",
        description=(
            "DNS Fingerprinting Tool — identify DNS server software and version.\n"
            "Targets may be IP addresses, hostnames, or (with -D) domain names.\n"
            "Pass '-' as a target to read addresses from stdin."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "target", nargs="*",
        help="Target DNS server(s) or domain name(s); use '-' to read from stdin",
    )
    parser.add_argument(
        "-p", "--port", type=int, default=53,
        help="DNS port (default: 53)",
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=5,
        help="Per-query timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "-r", "--retry", type=int, default=1,
        help="Retries for failed queries (default: 1)",
    )
    parser.add_argument(
        "--file", metavar="FILE",
        help="Read targets from FILE, one per line",
    )
    parser.add_argument(
        "-F", "--fork", type=int, default=10,
        help="Maximum parallel workers (default: 10)",
    )
    parser.add_argument(
        "-Q", "--source", type=str,
        help="Source IP address to use for outgoing queries",
    )
    parser.add_argument(
        "-s", "--short", action="store_true",
        help="Short / tabular output (IP padded to 15 chars, then result)",
    )
    parser.add_argument(
        "-S", "--separator", type=str, default=" ",
        help="Column separator for -s output (default: single space)",
    )
    parser.add_argument(
        "-T", "--force-tcp", action="store_true",
        help="Force TCP instead of UDP",
    )
    parser.add_argument(
        "-D", "--domain-ns", action="store_true",
        help="Fingerprint all authoritative NS servers for the given domain",
    )
    parser.add_argument(
        "-f", "--qchaos", action="store_true",
        help="Always query version.bind CH TXT (implies -V)",
    )
    parser.add_argument(
        "-V", "--qversion", action="store_true",
        help="Query server for version string (version.bind or version.server)",
    )
    parser.add_argument(
        "-d", "--debug", action="store_true",
        help="Enable debug output",
    )
    parser.add_argument(
        "-v", "--version", action="version",
        version=f"%(prog)s {DNSFingerprint.VERSION}",
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Collect targets
    # ------------------------------------------------------------------
    targets = []

    if args.file:
        try:
            with open(args.file) as fh:
                targets.extend(line.strip() for line in fh if line.strip())
        except OSError as exc:
            print(f"fpdns: cannot open {args.file}: {exc}", file=sys.stderr)
            sys.exit(1)

    # Allow '-' as a sentinel to read remaining targets from stdin
    positional = args.target or []
    if positional and positional[0] == "-":
        targets.extend(line.strip() for line in sys.stdin if line.strip())
        targets.extend(positional[1:])
    else:
        targets.extend(positional)

    if not targets:
        parser.print_help()
        sys.exit(1)

    # ------------------------------------------------------------------
    # Build engine
    # ------------------------------------------------------------------
    engine = DNSFingerprint(
        source=args.source,
        timeout=args.timeout,
        retry=args.retry,
        forcetcp=args.force_tcp,
        debug=args.debug,
        qversion=args.qversion or args.qchaos,
        qchaos=args.qchaos,
    )

    # ------------------------------------------------------------------
    # Fingerprint targets (sequential or parallel)
    # ------------------------------------------------------------------
    def _job(target):
        return _process_target(
            engine, target,
            port=args.port,
            short=args.short,
            separator=args.separator,
            domain_mode=args.domain_ns,
        )

    max_workers = max(1, args.fork)

    if max_workers == 1 or len(targets) == 1:
        for target in targets:
            for line in _job(target):
                print(line)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_job, t): t for t in targets}
            for future in concurrent.futures.as_completed(futures):
                try:
                    for line in future.result():
                        print(line)
                except Exception as exc:
                    t = futures[future]
                    print(f"error processing {t}: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
