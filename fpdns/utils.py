"""DNS resolution utilities for fpdns."""

import re
import socket

import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.exception

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_IPV6_RE = re.compile(
    r"^(((?=(?>.*?::)(?!.*::)))(::)?([0-9A-F]{1,4}::?){0,5}|"
    r"([0-9A-F]{1,4}:){6})(\\2([0-9A-F]{1,4}(::?|$)){0,2}|"
    r"((25[0-5]|(2[0-4]|1[0-9]|[1-9])?[0-9])(\\.|$)){4}|"
    r"[0-9A-F]{1,4}:[0-9A-F]{1,4})(?<![^:]:)(?<!\\.)$",
    re.IGNORECASE,
)


def is_ip(addr):
    """Return True if *addr* is a valid IPv4 or IPv6 address."""
    return bool(_IPV4_RE.match(addr)) or _is_ipv6(addr)


def _is_ipv6(addr):
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except (socket.error, OSError):
        return False


def resolve_to_ips(name, use_tcp=False, source=None):
    """Resolve *name* to a list of IP address strings.

    If *name* is already an IP address it is returned as-is.
    Tries A then AAAA records.
    Returns an empty list if resolution fails.
    """
    if is_ip(name):
        return [name]

    resolver = dns.resolver.Resolver()
    if use_tcp:
        resolver.use_tcp = True

    addresses = []
    for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
        try:
            answers = resolver.resolve(name, rdtype)
            for rdata in answers:
                addresses.append(rdata.address)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception:
            pass

    return addresses


def get_ns_ips(domain, use_tcp=False, source=None):
    """Return all IP addresses of the authoritative nameservers for *domain*.

    Queries NS records for the domain, then resolves each NS hostname to
    both A and AAAA addresses.
    Returns a list of (ns_hostname, ip_address) tuples.
    """
    resolver = dns.resolver.Resolver()
    if use_tcp:
        resolver.use_tcp = True

    ns_names = []
    try:
        answers = resolver.resolve(domain, dns.rdatatype.NS)
        for rdata in answers:
            ns_names.append(rdata.target.to_text(omit_final_dot=True))
    except Exception:
        return []

    results = []
    for ns in ns_names:
        for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            try:
                answers = resolver.resolve(ns, rdtype)
                for rdata in answers:
                    results.append((ns, rdata.address))
            except Exception:
                pass

    return results
