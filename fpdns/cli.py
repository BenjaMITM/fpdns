import sys
import argparse 
import re
from .fingerprint import DNSFingerprint


IPV4_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
IPV6_PATTERN = re.compile(
    r'^(((?=(?>.*?::)(?!.*::)))(::)?([0-9A-F]{1,4}::?){0,5}|'
    r'([0-9A-F]{1,4}:){6})(\\2([0-9A-F]{1,4}(::?|$)){0,2}|'
    r'((25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])(\\.|$)){4}|'
    r'[0-9A-F]{1,4}:[0-9A-F]{1,4})(?<![^:]:)(?<!\\.)$',
    re.IGNORECASE
)

def is_valid_ip(addr):
    return bool(IPV4_PATTERN.match(addr) or IPV6_PATTERN.match(addr))

def main():
    parser = argparse.ArgumentParser(prog='fpdns', description='DNS Fingerprinting Tool - ID DNS server software and versions')
    parser.add_argument('target', nargs='*', help='Target DNS server(s) to fingerprint')
    parser.add_argument('-p', '--port', type=int, default=53, help='DNS port (default: 53)')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Query timeout in seconds (default: 5)')
    parser.add_argument('-r', '--retry', type=int, default=1, help='Number of retries for failed queries (default: 1)')
    parser.add_argument('-f', '--file', type=str, help='Read targets from file (one per line)')
    parser.add_argument('-F', '--fork', type=int, default=10, help='Parallel processes (default: 10)')
    parser.add_argument('-T', '--timeout-total', type=int, default=0, help='Total timeout for all queries.')
    parser.add_argument('-s', '--source', type=str, help='Source IP address for queries')
    parser.add_argument('-tcp', '--force-tcp', action='store_true', help='Force TCP queries')
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {DNSFingerprint.VERSION}')
    parser.add_argument('-V', '--qversion', action='store_true', help='Query server for version info')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
    args = parser.parse_args()

    targets = []

    if args.file:
        with open(args.file, 'r') as f:
            targets.extend([line.strip() for line in f if line.strip()])

    targets.extend(args.target)

    if not targets:
        parser.print_help()
        sys.exit(1)

    fp = DNSFingerprint(
        source=args.source,
        timeout=args.timeout,
        retry=args.retry,
        forcetcp=args.force_tcp,
        debug=args.debug,
        qversion=args.qversion
    )

    for target in targets:
        if not is_valid_ip(target):
            print(f"Invalid IP address: {target}", file=sys.stderr)
            continue

        result = fp.string(target, args.port)
        print(f"{target}: {result}")
        
        if args.query_version:
            version = fp.query_version(target, args.port)
            print(f"{target} {version}")

if __name__ == "__main__":
    main()
    