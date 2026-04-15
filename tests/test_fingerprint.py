"""Tests for fpdns.fingerprint — covers packet building, header parsing,
rule matching, and the public API without requiring a live DNS server."""

import re
import struct
import socket
import unittest
from unittest.mock import patch, MagicMock

import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from fpdns.fingerprint import (
    DNSFingerprint,
    _QY, _NCT, _IQ, _QY_OLD, _IQ_OLD,
    _RULESET, _OLD_RULESET,
    _ShortHeaderError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(fp_str):
    """Build a minimal dns.message.Message whose header matches *fp_str*."""
    parts = fp_str.split(",")
    qr, opcode_s, aa, tc, rd, ra, ad, cd, rcode_s = (
        int(parts[0]), parts[1], int(parts[2]), int(parts[3]),
        int(parts[4]), int(parts[5]), int(parts[6]), int(parts[7]),
        parts[8],
    )

    msg = dns.message.Message()
    flags = 0
    if qr: flags |= dns.flags.QR
    if aa: flags |= dns.flags.AA
    if tc: flags |= dns.flags.TC
    if rd: flags |= dns.flags.RD
    if ra: flags |= dns.flags.RA
    if ad: flags |= dns.flags.AD
    if cd: flags |= dns.flags.CD
    try:
        flags |= dns.opcode.to_flags(dns.opcode.from_text(opcode_s))
    except Exception:
        pass
    msg.flags = flags
    try:
        msg.set_rcode(dns.rcode.from_text(rcode_s))
    except Exception:
        pass

    # Populate section counts from the remaining fields
    qdcount = int(parts[9])
    ancount = int(parts[10])
    nscount = int(parts[11])
    arcount = int(parts[12])

    root = dns.name.from_text(".")
    for _ in range(qdcount):
        msg.question.append(dns.rrset.RRset(root, dns.rdataclass.IN, dns.rdatatype.A))
    for _ in range(ancount):
        msg.answer.append(dns.rrset.RRset(root, dns.rdataclass.IN, dns.rdatatype.A))
    for _ in range(nscount):
        msg.authority.append(dns.rrset.RRset(root, dns.rdataclass.IN, dns.rdatatype.A))
    for _ in range(arcount):
        msg.additional.append(dns.rrset.RRset(root, dns.rdataclass.IN, dns.rdatatype.A))

    return msg


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestDataIntegrity(unittest.TestCase):
    """Sanity-check the embedded ruleset data."""

    def test_qy_length(self):
        self.assertEqual(len(_QY), 12)

    def test_nct_length(self):
        self.assertEqual(len(_NCT), 12)

    def test_iq_length(self):
        self.assertEqual(len(_IQ), 31)

    def test_qy_old_length(self):
        self.assertEqual(len(_QY_OLD), 9)

    def test_iq_old_length(self):
        self.assertEqual(len(_IQ_OLD), 102)

    def test_qy_format(self):
        for i, h in enumerate(_QY):
            self.assertEqual(len(h.split(",")), 13, f"_QY[{i}] has wrong field count")

    def test_iq_format(self):
        for i, p in enumerate(_IQ):
            self.assertEqual(len(p.split(",")), 13, f"_IQ[{i}] has wrong field count")

    def test_ruleset_has_entries(self):
        self.assertGreater(len(_RULESET), 0)

    def test_old_ruleset_has_entries(self):
        self.assertGreater(len(_OLD_RULESET), 0)


class TestBuildPacket(unittest.TestCase):
    """Tests for DNSFingerprint._build_packet."""

    def _parse_header(self, wire):
        return struct.unpack("!HHHHHH", wire[:12])

    def test_basic_query_packet(self):
        wire = DNSFingerprint._build_packet(_QY[0], _NCT[0])
        _, flags, qd, an, ns, ar = self._parse_header(wire)
        # qy[0] has all zeros for counts; QR=0, QUERY opcode, NOERROR
        self.assertEqual(qd, 0)
        self.assertEqual(an, 0)
        self.assertEqual(flags & dns.flags.QR, 0)

    def test_notify_packet(self):
        wire = DNSFingerprint._build_packet(_QY[2], _NCT[2])
        _, flags, qd, an, ns, ar = self._parse_header(wire)
        # qy[2]: "0,NOTIFY,0,1,1,0,1,1,NOTIMP,0,0,0,0"
        self.assertEqual(qd, 0)
        self.assertEqual(an, 0)
        op = dns.opcode.from_flags(flags)
        self.assertEqual(dns.opcode.to_text(op), "NOTIFY")

    def test_counts_overridden(self):
        # qy[1] has ra=1, ad=0, cd=1 in position
        header = "0,QUERY,0,0,0,0,0,0,NOERROR,3,2,1,0"
        wire = DNSFingerprint._build_packet(header, ". IN A")
        _, _, qd, an, ns, ar = self._parse_header(wire)
        self.assertEqual(qd, 3)
        self.assertEqual(an, 2)
        self.assertEqual(ns, 1)
        self.assertEqual(ar, 0)

    def test_chaos_class(self):
        # Should not raise for CH class queries
        wire = DNSFingerprint._build_packet(_QY[4], _NCT[4])
        self.assertIsInstance(wire, bytes)
        self.assertGreater(len(wire), 12)

    def test_unknown_type_falls_back(self):
        # MAILB is obscure; should not crash
        wire = DNSFingerprint._build_packet(_QY_OLD[2], ". IN MAILB")
        self.assertIsInstance(wire, bytes)

    def test_bad_header_raises(self):
        with self.assertRaises(ValueError):
            DNSFingerprint._build_packet("not,valid", ". IN A")


class TestHeaderToFp(unittest.TestCase):
    """Tests for DNSFingerprint._header_to_fp."""

    def test_nsd_response(self):
        msg = _make_response(_IQ[0])
        fp = DNSFingerprint._header_to_fp(msg)
        self.assertEqual(fp, _IQ[0])

    def test_noerror_response(self):
        msg = _make_response(_IQ[2])
        fp = DNSFingerprint._header_to_fp(msg)
        self.assertEqual(fp, _IQ[2])

    def test_notify_response(self):
        msg = _make_response(_IQ[4])
        fp = DNSFingerprint._header_to_fp(msg)
        self.assertEqual(fp, _IQ[4])

    def test_roundtrip_all_iq(self):
        """Every _IQ pattern that contains no regex meta-chars must survive a
        build → parse → header_to_fp round-trip."""
        for i, pat in enumerate(_IQ):
            if re.search(r"[.+*?\\|()[\]{}^$]", pat):
                continue  # skip regex patterns
            with self.subTest(iq=i):
                msg = _make_response(pat)
                fp = DNSFingerprint._header_to_fp(msg)
                self.assertEqual(fp, pat)


class TestProcessMatching(unittest.TestCase):
    """Tests for the _process rule-matching engine using mocked probes."""

    def setUp(self):
        self.fp = DNSFingerprint(timeout=1)

    def _mock_probe(self, response_fp_str):
        """Return a (message, '') pair for the given fingerprint string."""
        msg = _make_response(response_fp_str)
        return (msg, "")

    def test_nsd_3x_identified(self):
        with patch.object(self.fp, "_probe", return_value=self._mock_probe(_IQ[0])):
            result = self.fp._process("1.2.3.4", 53, _QY[0], _NCT[0], _RULESET, "New")
        self.assertEqual(result["vendor"], "NLnetLabs")
        self.assertEqual(result["product"], "NSD")
        self.assertIn("3.1.0", result["version"])

    def test_eagle_dns_11(self):
        with patch.object(self.fp, "_probe", return_value=self._mock_probe(_IQ[1])):
            result = self.fp._process("1.2.3.4", 53, _QY[0], _NCT[0], _RULESET, "New")
        self.assertEqual(result["product"], "Eagle DNS")
        self.assertEqual(result["version"], "1.1.1")

    def test_eagle_dns_10(self):
        with patch.object(self.fp, "_probe", return_value=self._mock_probe(_IQ[2])):
            result = self.fp._process("1.2.3.4", 53, _QY[0], _NCT[0], _RULESET, "New")
        self.assertEqual(result["product"], "Eagle DNS")
        self.assertIn("1.0", result["version"])

    def test_timeout_returns_timeout_string(self):
        with patch.object(self.fp, "_probe", return_value=(None, "query timed out")):
            result = self.fp._process("1.2.3.4", 53, _QY[0], _NCT[0], _RULESET, "New")
        # A timeout on the initial probe won't match any pattern in the new ruleset
        self.assertFalse(result.get("product"))

    def test_no_match_returns_empty(self):
        # A completely unknown fingerprint
        unknown = "1,QUERY,1,1,1,1,1,1,NOERROR,5,5,5,5"
        with patch.object(self.fp, "_probe", return_value=self._mock_probe(unknown)):
            result = self.fp._process("1.2.3.4", 53, _QY[0], _NCT[0], _RULESET, "New")
        self.assertEqual(result, {})

    def test_ruleset_name_recorded(self):
        with patch.object(self.fp, "_probe", return_value=self._mock_probe(_IQ[0])):
            result = self.fp._process("1.2.3.4", 53, _QY[0], _NCT[0], _RULESET, "TestSet")
        self.assertEqual(result["ruleset"], "TestSet")


class TestRecursiveMatching(unittest.TestCase):
    """Test that nested rulesets and recursion work correctly."""

    def setUp(self):
        self.fp = DNSFingerprint(timeout=1)

    def _make_probe_sequence(self, responses):
        """Return a side_effect list for _probe that yields each response in turn."""
        calls = iter(responses)

        def _side(*args, **kwargs):
            fp_str = next(calls)
            if fp_str is None:
                return (None, "query timed out")
            return (_make_response(fp_str), "")

        return _side

    def test_nsd_4x_identified_after_notify(self):
        """NSD 4.x requires a second NOTIFY probe to distinguish from NSD 3.x."""
        side = self._make_probe_sequence([_IQ[29], _IQ[30]])
        with patch.object(self.fp, "_probe", side_effect=side):
            result = self.fp._init("1.2.3.4", 53)
        self.assertEqual(result["product"], "NSD")
        self.assertIn("4.1.10", result["version"])

    def test_windows_dns_2008_r2(self):
        """Windows DNS 2008 R2 requires multiple probes timing out."""
        # _IQ[3] is a regex "...NOERROR,.+,.+,.+,.+" — use a concrete match
        iq3_concrete = "1,QUERY,0,0,0,1,0,0,NOERROR,1,1,1,1"
        side = self._make_probe_sequence([
            iq3_concrete,  # initial: recurse into qy[1]
            iq3_concrete,  # qy[1]: recurse into qy[2]
            None,          # qy[2]: timeout → recurse into qy[3]
            None,          # qy[3]: timeout → recurse into qy[4]
            None,          # qy[4]: timeout → recurse into qy[5]
            None,          # qy[5]: timeout → match "2008 R2"
        ])
        with patch.object(self.fp, "_probe", side_effect=side):
            result = self.fp._init("1.2.3.4", 53)
        self.assertEqual(result["product"], "Windows DNS")
        self.assertIn("2008 R2", result["version"])

    def test_google_dns(self):
        """Google DNS identified via SERVFAIL on NOTIFY + IQUERY SERVFAIL."""
        # _IQ[3] is a regex — use a concrete string that satisfies it
        iq3_concrete = "1,QUERY,0,0,0,1,0,0,NOERROR,1,1,1,1"
        side = self._make_probe_sequence([
            iq3_concrete,  # initial match → recurse qy[1]
            iq3_concrete,  # qy[1] match → recurse qy[2]
            _IQ[12],       # qy[2]: NOTIFY SERVFAIL → recurse qy[6]
            _IQ[13],       # qy[6]: IQUERY SERVFAIL → Google DNS
        ])
        with patch.object(self.fp, "_probe", side_effect=side):
            result = self.fp._init("1.2.3.4", 53)
        self.assertEqual(result["product"], "Google DNS")

    def test_unbound_1_7_to_1_9(self):
        """Unbound 1.7–1.9.6 identified via REFUSED + FORMERR."""
        # _IQ[23] = "1,QUERY,0,0,0,.+,0,0,REFUSED,.+,0,0,0" — use a concrete match
        iq23_concrete = "1,QUERY,0,0,0,1,0,0,REFUSED,1,0,0,0"
        side = self._make_probe_sequence([
            iq23_concrete,  # initial → recurse qy[0]
            _IQ[25],        # qy[0] match (literal) → recurse qy[10]
            _IQ[28],        # qy[10] → Unbound 1.7.0 -- 1.9.6
        ])
        with patch.object(self.fp, "_probe", side_effect=side):
            result = self.fp._init("1.2.3.4", 53)
        self.assertEqual(result["product"], "Unbound")
        self.assertIn("1.7.0", result["version"])


class TestStringOutput(unittest.TestCase):
    """Test the public string() method."""

    def setUp(self):
        self.fp = DNSFingerprint(timeout=1)

    def test_string_nsd(self):
        with patch.object(self.fp, "_probe",
                          return_value=(_make_response(_IQ[0]), "")):
            s = self.fp.string("1.2.3.4")
        self.assertIn("NSD", s)
        self.assertIn("NLnetLabs", s)

    def test_string_error(self):
        with patch.object(self.fp, "_probe",
                          return_value=(None, "connection failed")):
            # An all-timeout run returns {} from _init, string() returns "Unknown"
            s = self.fp.string("1.2.3.4")
        self.assertIsInstance(s, str)

    def test_string_unknown(self):
        with patch.object(self.fp, "_init", return_value={}):
            s = self.fp.string("1.2.3.4")
        self.assertEqual(s, "Unknown")


class TestCaching(unittest.TestCase):
    """Verify that probe results are cached within a single fingerprinting run."""

    def test_same_probe_not_sent_twice(self):
        fp = DNSFingerprint(timeout=1)
        msg = _make_response(_IQ[0])
        call_count = 0

        original_send = fp._send_recv_raw

        def counting_send(wire, target, port):
            nonlocal call_count
            call_count += 1
            return msg

        fp._send_recv_raw = counting_send
        fp._probe("1.2.3.4", 53, _QY[0], _NCT[0])
        fp._probe("1.2.3.4", 53, _QY[0], _NCT[0])  # should hit cache
        self.assertEqual(call_count, 1)


class TestQueryVersion(unittest.TestCase):
    """Tests for the query_version method."""

    def test_returns_unavailable_on_failure(self):
        fp = DNSFingerprint(timeout=1)
        with patch("dns.query.udp", side_effect=Exception("refused")):
            result = fp.query_version("1.2.3.4", 53, "version.bind")
        self.assertIn("unavailable", result)

    def test_returns_version_string(self):
        fp = DNSFingerprint(timeout=1)
        mock_rdata = MagicMock()
        mock_rdata.strings = [b"BIND 9.11.0"]
        mock_rrset = MagicMock()
        mock_rrset.__iter__ = lambda self: iter([mock_rdata])
        mock_response = MagicMock()
        mock_response.answer = [mock_rrset]
        with patch("dns.query.udp", return_value=mock_response):
            result = fp.query_version("1.2.3.4", 53, "version.bind")
        self.assertIn("BIND 9.11.0", result)


class TestInitFallback(unittest.TestCase):
    """Verify _init falls back to old ruleset when new ruleset finds nothing."""

    def test_falls_back_to_old_ruleset(self):
        fp = DNSFingerprint(timeout=1)
        # New ruleset won't match an all-zeros response
        no_match = "1,QUERY,1,1,1,1,1,1,NOERROR,9,9,9,9"
        # Old ruleset first probe gets dnsmasq fingerprint
        dnsmasq = _IQ_OLD[89]  # "1,QUERY,1,0,1,1,0,0,NXDOMAIN,1,0,0,0"

        call_count = [0]

        def side(target, port, header_str, query_str, ignore_recurse=False):
            call_count[0] += 1
            if not ignore_recurse:
                return (_make_response(no_match), "")
            else:
                return (_make_response(dnsmasq), "")

        with patch.object(fp, "_probe", side_effect=side):
            result = fp._init("1.2.3.4", 53)

        self.assertEqual(result.get("product"), "dnsmasq")
        self.assertGreater(call_count[0], 1)
