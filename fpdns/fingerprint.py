import re
import socket
import struct

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

# ---------------------------------------------------------------------------
# Query header templates (sent to the target server)
# Format: qr,opcode,aa,tc,rd,ra,ad,cd,rcode,qdcount,ancount,nscount,arcount
# ---------------------------------------------------------------------------
_QY = [
    "0,QUERY,0,0,0,0,0,0,NOERROR,0,0,0,0",          # qy[0]
    "0,QUERY,0,0,0,1,0,1,NOERROR,0,0,0,0",          # qy[1]
    "0,NOTIFY,0,1,1,0,1,1,NOTIMP,0,0,0,0",          # qy[2]
    "0,IQUERY,0,0,0,1,1,1,NOERROR,0,0,0,0",         # qy[3]
    "0,QUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",          # qy[4]
    "0,QUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",          # qy[5]
    "0,IQUERY,0,1,1,0,0,0,NOTIMP,0,0,0,0",          # qy[6]
    "0,QUERY,0,0,0,0,0,1,NOTIMP,0,0,0,0",           # qy[7]
    "0,UPDATE,0,0,1,0,0,0,NOERROR,0,0,0,0",         # qy[8]
    "0,QUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",          # qy[9]
    "0,QUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",          # qy[10]
    "0,QUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",          # qy[11]
]

# Query content templates (what to ask for)
_NCT = [
    ". IN A",                   # nct[0]
    ". IN A",                   # nct[1]
    ". IN A",                   # nct[2]
    ". IN A",                   # nct[3]
    "jjjjjjjjjjjj. CH A",      # nct[4]
    "jjjjjjjjjjjj. CH RRSIG",  # nct[5]
    ". IN A",                   # nct[6]
    ". IN A",                   # nct[7]
    ". IN A",                   # nct[8]
    ". IN DNSKEY",              # nct[9]
    "jjjjjjjjjjjj. ANY TKEY",  # nct[10]
    ". IN IXFR",                # nct[11]
]

# Expected response fingerprint patterns (new ruleset)
_IQ = [
    "1,QUERY,0,0,0,0,0,0,SERVFAIL,1,0,0,0",         # iq[0]
    "1,QUERY,0,0,0,0,0,0,NXDOMAIN,1,0,0,0",         # iq[1]
    "1,QUERY,0,0,0,0,0,0,NOERROR,1,0,0,0",          # iq[2]
    "1,QUERY,0,0,0,1,0,0,NOERROR,.+,.+,.+,.+",      # iq[3]
    "1,NOTIFY,0,0,1,1,0,1,FORMERR,1,0,0,0",         # iq[4]
    "1,NOTIFY,0,0,1,1,0,0,FORMERR,1,0,0,0",         # iq[5]
    "1,NOTIFY,0,0,1,1,0,0,REFUSED,1,0,0,0",         # iq[6]
    "0,NOTIFY,0,1,1,0,1,1,NOTIMP,1,0,0,0",          # iq[7]
    "1,IQUERY,0,0,0,1,0,0,NOTIMP,1,0,0,0",          # iq[8]
    "0,IQUERY,0,0,0,1,1,1,NOERROR,1,0,0,0",         # iq[9]
    "1,QUERY,0,0,1,0,0,0,NOTIMP,1,0,0,0",           # iq[10]
    "0,QUERY,0,0,1,0,0,0,NOERROR,1,0,0,0",          # iq[11]
    "1,NOTIFY,0,0,1,1,0,0,SERVFAIL,1,0,0,0",        # iq[12]
    "1,IQUERY,0,0,1,1,0,0,SERVFAIL,1,0,0,0",        # iq[13]
    "1,IQUERY,0,0,1,1,0,0,NOTIMP,0,0,0,0",          # iq[14]
    "1,QUERY,0,0,0,1,0,0,NOTIMP,.+,.+,.+,.+",       # iq[15]
    "1,QUERY,0,0,0,1,0,1,NOERROR,.+,.+,.+,.+",      # iq[16]
    "1,UPDATE,0,0,1,1,0,0,FORMERR,1,0,0,0",         # iq[17]
    "1,QUERY,0,0,1,0,0,0,SERVFAIL,1,0,0,0",         # iq[18]
    "1,QUERY,0,0,1,0,0,0,REFUSED,1,0,0,0",          # iq[19]
    "1,UPDATE,0,0,1,1,0,0,FORMERR,0,0,0,0",         # iq[20]
    "1,QUERY,0,0,1,1,0,0,NOERROR,.+,.+,.+,.+",      # iq[21]
    "1,QUERY,0,1,1,1,0,0,NOERROR,.+,.+,.+,.+",      # iq[22]
    "1,QUERY,0,0,0,.+,0,0,REFUSED,.+,0,0,0",        # iq[23]
    "1,QUERY,0,0,0,0,0,0,REFUSED,0,0,0,0",          # iq[24]
    "1,QUERY,0,0,0,1,0,0,REFUSED,1,0,0,0",          # iq[25]
    "1,QUERY,0,0,1,1,0,0,REFUSED,1,0,0,0",          # iq[26]
    "1,QUERY,0,0,1,1,0,0,NXDOMAIN,.+,.+,.+,.+",     # iq[27]
    "1,QUERY,0,0,1,0,0,0,FORMERR,1,0,0,0",          # iq[28]
    "1,QUERY,0,0,0,0,0,0,REFUSED,1,0,0,0",          # iq[29]
    "1,NOTIFY,0,0,1,0,0,0,FORMERR,0,0,0,0",         # iq[30]
]

# ---------------------------------------------------------------------------
# Old query templates (legacy servers: BIND 4/8, early 9.x, etc.)
# ---------------------------------------------------------------------------
_QY_OLD = [
    "0,IQUERY,0,0,1,0,0,0,NOERROR,0,0,0,0",         # qy_old[0]
    "0,NOTIFY,0,0,0,0,0,0,NOERROR,0,0,0,0",         # qy_old[1]
    "0,QUERY,0,0,0,0,0,0,NOERROR,0,0,0,0",          # qy_old[2]
    "0,IQUERY,0,0,0,0,1,1,NOERROR,0,0,0,0",         # qy_old[3]
    "0,QUERY,0,0,0,0,0,0,NOTIMP,0,0,0,0",           # qy_old[4]
    "0,IQUERY,1,0,1,1,1,1,NOERROR,0,0,0,0",         # qy_old[5]
    "0,UPDATE,0,0,0,1,0,0,NOERROR,0,0,0,0",         # qy_old[6]
    "0,QUERY,1,1,1,1,1,1,NOERROR,0,0,0,0",          # qy_old[7]
    "0,QUERY,0,0,0,0,0,1,NOERROR,0,0,0,0",          # qy_old[8]
]

# Old response fingerprint patterns
_IQ_OLD = [
    "1,IQUERY,0,0,1,0,0,0,FORMERR,0,0,0,0",         # iq_old[0]
    "1,IQUERY,0,0,1,0,0,0,FORMERR,1,0,0,0",         # iq_old[1]
    "1,IQUERY,0,0,1,0,0,0,NOTIMP,0,0,0,0",          # iq_old[2]
    "1,IQUERY,0,0,1,0,0,0,NOTIMP,1,0,0,0",          # iq_old[3]
    "1,IQUERY,0,0,1,1,0,0,FORMERR,0,0,0,0",         # iq_old[4]
    "1,IQUERY,0,0,1,1,0,0,NOTIMP,0,0,0,0",          # iq_old[5]
    "1,IQUERY,0,0,1,1,0,0,NOTIMP,1,0,0,0",          # iq_old[6]
    "1,IQUERY,1,0,1,0,0,0,NOTIMP,1,0,0,0",          # iq_old[7]
    "1,QUERY,1,0,1,0,0,0,NOTIMP,1,0,0,0",           # iq_old[8]
    "1,QUERY,0,0,0,0,0,0,NOTIMP,0,0,0,0",           # iq_old[9]
    "1,IQUERY,0,0,1,1,0,0,FORMERR,1,0,0,0",         # iq_old[10]
    "1,NOTIFY,0,0,0,0,0,0,FORMERR,1,0,0,0",         # iq_old[11]
    "1,NOTIFY,0,0,0,0,0,0,NOTIMP,0,0,0,0",          # iq_old[12]
    "1,NOTIFY,0,0,0,0,0,0,NOTIMP,1,0,0,0",          # iq_old[13]
    "1,NOTIFY,0,0,0,0,0,0,NXDOMAIN,1,0,0,0",        # iq_old[14]
    "1,NOTIFY,0,0,0,0,0,0,REFUSED,1,0,0,0",         # iq_old[15]
    "1,NOTIFY,0,0,0,0,0,0,SERVFAIL,1,0,0,0",        # iq_old[16]
    "1,NOTIFY,0,0,0,1,0,0,FORMERR,1,0,0,0",         # iq_old[17]
    "1,NOTIFY,0,0,0,1,0,0,NOTIMP,0,0,0,0",          # iq_old[18]
    "1,NOTIFY,0,0,0,1,0,0,NOTIMP,1,0,0,0",          # iq_old[19]
    "1,NOTIFY,0,0,0,1,0,0,REFUSED,1,0,0,0",         # iq_old[20]
    "1,NOTIFY,0,0,0,1,0,0,SERVFAIL,1,0,0,0",        # iq_old[21]
    "1,NOTIFY,1,0,0,0,0,0,NOTIMP,1,0,0,0",          # iq_old[22]
    "1,QUERY,1,0,0,0,0,0,NOTIMP,1,0,0,0",           # iq_old[23]
    "1,NOTIFY,1,0,0,0,0,0,SERVFAIL,1,0,0,0",        # iq_old[24]
    "1,IQUERY,0,0,0,0,1,1,NOTIMP,0,0,0,0",          # iq_old[25]
    "1,IQUERY,0,0,0,0,0,0,NOTIMP,0,0,0,0",          # iq_old[26]
    "1,IQUERY,0,0,1,1,1,1,FORMERR,0,0,0,0",         # iq_old[27]
    "1,IQUERY,1,0,1,1,1,1,FORMERR,0,0,0,0",         # iq_old[28]
    "1,QUERY,.,0,1,.,.,.,NOTIMP,.+,.+,.+,.+",       # iq_old[29]
    "1,QUERY,.,0,1,.,.,.,.+,.+,.+,.+,.+",           # iq_old[30]
    "1,QUERY,0,0,.,.,0,0,NXDOMAIN,1,0,0,0",         # iq_old[31]
    "1,QUERY,0,0,.,.,0,0,FORMERR,1,0,0,0",          # iq_old[32]
    "1,UPDATE,0,0,0,0,0,0,NOTIMP,0,0,0,0",          # iq_old[33]
    "1,UPDATE,0,0,0,1,0,0,NOTIMP,0,0,0,0",          # iq_old[34]
    "1,QUERY,0,0,1,0,0,0,NOERROR,1,0,0,0",          # iq_old[35]
    "1,QUERY,1,1,1,1,1,1,NOTIMP,1,0,0,0",           # iq_old[36]
    "1,QUERY,0,0,0,0,0,0,NOERROR,1,0,.+,0",         # iq_old[37]
    "1,QUERY,0,0,1,0,0,0,FORMERR,1,0,0,0",          # iq_old[38]
    "1,IQUERY,0,0,1,0,1,1,NOTIMP,1,0,0,0",          # iq_old[39]
    "1,IQUERY,0,0,0,1,1,1,REFUSED,1,0,0,0",         # iq_old[40]
    "1,UPDATE,0,0,0,1,0,0,REFUSED,1,0,0,0",         # iq_old[41]
    "1,IQUERY,0,0,0,1,1,1,FORMERR,0,0,0,0",         # iq_old[42]
    "1,IQUERY,0,0,0,1,0,0,NOTIMP,0,0,0,0",          # iq_old[43]
    "1,QUERY,1,0,1,0,0,0,FORMERR,1,0,0,0",          # iq_old[44]
    "1,UPDATE,0,0,0,0,0,0,FORMERR,1,0,0,0",         # iq_old[45]
    "1,UPDATE,0,0,0,0,0,0,FORMERR,0,0,0,0",         # iq_old[46]
    "1,QUERY,0,0,1,0,0,0,FORMERR,0,0,0,0",          # iq_old[47]
    "1,QUERY,0,0,1,0,0,0,SERVFAIL,1,0,0,0",         # iq_old[48]
    "1,QUERY,1,0,1,0,0,0,NXDOMAIN,1,0,1,0",         # iq_old[49]
    "1,QUERY,0,0,1,0,0,0,REFUSED,1,0,0,0",          # iq_old[50]
    "1,QUERY,0,0,1,0,0,0,NOERROR,1,1,0,0",          # iq_old[51]
    "1,IQUERY,0,0,1,0,0,0,REFUSED,0,0,0,0",         # iq_old[52]
    "1,QUERY,0,0,0,0,0,0,FORMERR,0,0,0,0",          # iq_old[53]
    "1,QUERY,0,0,1,1,1,0,NOERROR,1,0,1,0",          # iq_old[54]
    "1,QUERY,0,0,1,1,0,0,NOERROR,1,0,1,0",          # iq_old[55]
    "1,QUERY,0,0,1,0,1,0,NOERROR,.+,.+,.+,.+",      # iq_old[56]
    "1,QUERY,0,0,1,0,0,0,.+,.+,.+,.+,.+",           # iq_old[57]
    "1,QUERY,1,0,1,0,0,0,NOERROR,1,1,0,0",          # iq_old[58]
    "1,QUERY,0,0,1,1,0,0,SERVFAIL,1,0,0,0",         # iq_old[59]
    "1,QUERY,1,0,1,1,0,0,NOERROR,1,1,0,0",          # iq_old[60]
    "1,QUERY,0,0,1,1,0,0,REFUSED,1,0,0,0",          # iq_old[61]
    "1,QUERY,0,0,0,0,0,0,NOTIMP,1,0,0,0",           # iq_old[62]
    "1,QUERY,1,0,1,1,0,0,NOERROR,1,0,1,0",          # iq_old[63]
    "1,IQUERY,0,0,1,1,1,1,NOTIMP,0,0,0,0",          # iq_old[64]
    "1,UPDATE,0,0,0,0,0,0,REFUSED,0,0,0,0",         # iq_old[65]
    "1,IQUERY,0,0,0,1,1,1,NOTIMP,1,0,0,0",          # iq_old[66]
    "1,IQUERY,0,0,0,1,0,0,NOTIMP,1,0,0,0",          # iq_old[67]
    "1,QUERY,0,1,1,1,1,1,NOERROR,1,0,.,0",          # iq_old[68]
    "1,QUERY,0,1,1,1,0,1,NOERROR,1,0,.,0",          # iq_old[69]
    "1,IQUERY,0,0,1,0,0,0,REFUSED,1,0,0,0",         # iq_old[70]
    "1,IQUERY,1,0,1,1,1,1,NOTIMP,1,0,0,0",          # iq_old[71]
    "1,IQUERY,0,0,1,0,0,0,NOERROR,1,0,0,0",         # iq_old[72]
    "1,QUERY,1,0,1,1,0,0,NOERROR,1,0,0,0",          # iq_old[73]
    "1,IQUERY,1,0,1,1,0,0,NXDOMAIN,1,0,0,0",        # iq_old[74]
    "1,UPDATE,0,0,0,1,0,0,FORMERR,0,0,0,0",         # iq_old[75]
    "1,IQUERY,1,0,1,0,0,0,NXDOMAIN,1,0,0,0",        # iq_old[76]
    "1,QUERY,0,0,1,1,0,0,FORMERR,1,0,0,0",          # iq_old[77]
    "1,QUERY,0,0,0,1,0,0,SERVFAIL,1,0,0,0",         # iq_old[78]
    "1,QUERY,0,0,1,1,0,0,NOERROR,1,1,0,0",          # iq_old[79]
    "1,IQUERY,1,0,1,0,0,0,NOERROR,1,0,1,0",         # iq_old[80]
    "1,IQUERY,1,0,1,1,0,0,NOTIMP,1,0,0,0",          # iq_old[81]
    "1,QUERY,0,0,1,1,0,0,NOERROR,1,0,0,0",          # iq_old[82]
    "1,QUERY,1,0,1,1,0,0,NOERROR,1,1,1,.+",         # iq_old[83]
    "1,QUERY,0,0,1,1,0,0,REFUSED,0,0,0,0",          # iq_old[84]
    "1,UPDATE,0,0,0,1,0,0,NOTIMP,1,0,0,0",          # iq_old[85]
    "1,QUERY,1,0,0,1,0,0,NXDOMAIN,1,0,0,0",         # iq_old[86]
    "1,QUERY,0,0,0,1,0,0,NOTIMP,0,0,0,0",           # iq_old[87]
    "1,QUERY,0,0,0,0,0,0,REFUSED,1,0,0,0",          # iq_old[88]
    "1,QUERY,1,0,1,1,0,0,NXDOMAIN,1,0,0,0",         # iq_old[89]
    "1,QUERY,1,0,0,0,0,0,NOERROR,1,1,0,0",          # iq_old[90]
    "1,IQUERY,1,0,1,1,0,1,NOTIMP,1,0,0,0",          # iq_old[91]
    "1,QUERY,0,0,0,1,0,0,NOTIMP,1,0,0,0",           # iq_old[92]
    "1,QUERY,0,0,1,0,0,1,SERVFAIL,1,0,0,0",         # iq_old[93]
    "1,QUERY,0,0,0,1,0,0,NOERROR,1,0,13,13",        # iq_old[94]
    "1,QUERY,0,0,0,1,0,0,NOERROR,1,0,1,0",          # iq_old[95]
    "1,QUERY,0,0,1,0,0,0,NOERROR,1,0,13,13",        # iq_old[96]
    "1,IQUERY,1,0,0,0,0,0,NOTIMP,1,0,0,0",          # iq_old[97]
    "1,IQUERY,1,0,0,0,1,1,NOTIMP,1,0,0,0",          # iq_old[98]
    "1,IQUERY,0,0,1,1,0,0,NOERROR,1,0,1,0",         # iq_old[99]
    "1,QUERY,.,0,1,0,0,0,NOERROR,1,0,0,0",          # iq_old[100]
    "1,QUERY,0,0,1,0,0,0,NXDOMAIN,1,0,0,0",         # iq_old[101]
]

# ---------------------------------------------------------------------------
# Decision-tree rulesets
#
# Each rule dict may have:
#   "pattern"  - regex matched against the response fingerprint string (required)
#   "result"   - dict or str; return this when matched (terminates recursion)
#   "state"    - debug state string; return no-match when matched
#   "header"   - header string for the *next* probe (requires "ruleset")
#   "query"    - query string for the next probe
#   "ruleset"  - list of child rules to recurse into
#   "qv"       - version-query ident (e.g. "version.bind")
# ---------------------------------------------------------------------------
_RULESET = [
    {
        "pattern": _IQ[0],
        "result": {"vendor": "NLnetLabs", "product": "NSD", "version": "3.1.0 -- 3.2.8"},
    },
    {
        "pattern": _IQ[1],
        "result": {"vendor": "Unlogic", "product": "Eagle DNS", "version": "1.1.1"},
    },
    {
        "pattern": _IQ[2],
        "result": {"vendor": "Unlogic", "product": "Eagle DNS", "version": "1.0 -- 1.0.1"},
    },
    {
        "pattern": _IQ[29],
        "header": _QY[2],
        "query": _NCT[2],
        "ruleset": [
            {
                "pattern": _IQ[30],
                "result": {"vendor": "NLnetLabs", "product": "NSD", "version": "4.1.10 -- 4.3.1"},
            },
        ],
    },
    {
        "pattern": _IQ[3],
        "header": _QY[1],
        "query": _NCT[1],
        "ruleset": [
            {
                "pattern": _IQ[3],
                "header": _QY[2],
                "query": _NCT[2],
                "ruleset": [
                    {
                        "pattern": _IQ[4],
                        "result": {"vendor": "ISC", "product": "BIND", "version": "9.3.0 -- 9.3.6-P1"},
                    },
                    {
                        "pattern": _IQ[5],
                        "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.3 -- 9.2.9"},
                    },
                    {
                        "pattern": _IQ[6],
                        "result": {"vendor": "ISC", "product": "BIND", "version": "9.1.1 -- 9.1.3"},
                    },
                    {
                        "pattern": "query timed out",
                        "header": _QY[3],
                        "query": _NCT[3],
                        "ruleset": [
                            {
                                "pattern": _IQ[8],
                                "result": {"vendor": "Microsoft", "product": "Windows DNS", "version": "2003"},
                            },
                            {
                                "pattern": "query timed out",
                                "header": _QY[4],
                                "query": _NCT[4],
                                "ruleset": [
                                    {
                                        "pattern": _IQ[10],
                                        "result": {"vendor": "Microsoft", "product": "Windows DNS", "version": "2003 R2"},
                                    },
                                    {
                                        "pattern": "query timed out",
                                        "header": _QY[5],
                                        "query": _NCT[5],
                                        "ruleset": [
                                            {
                                                "pattern": "query timed out",
                                                "result": {"vendor": "Microsoft", "product": "Windows DNS", "version": "2008 R2"},
                                            },
                                            {
                                                "pattern": _IQ[10],
                                                "result": {"vendor": "Microsoft", "product": "Windows DNS", "version": "2008"},
                                            },
                                            {"pattern": ".+", "state": "q0r3q1r3q2r7q3r9q4r11q5r?"},
                                        ],
                                    },
                                ],
                            },
                        ],
                    },
                    {
                        "pattern": _IQ[12],
                        "header": _QY[6],
                        "query": _NCT[6],
                        "ruleset": [
                            {
                                "pattern": _IQ[13],
                                "result": {"vendor": "", "product": "Google DNS", "version": ""},
                            },
                            {
                                "pattern": _IQ[14],
                                "header": _QY[7],
                                "query": _NCT[7],
                                "ruleset": [
                                    {
                                        "pattern": _IQ[15],
                                        "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.0rc3"},
                                    },
                                    {
                                        "pattern": _IQ[3],
                                        "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.0 -- 9.2.2-P3"},
                                    },
                                    {"pattern": ".+", "state": "q0r3q1r3q2r7r12q6r14q7r?"},
                                ],
                            },
                        ],
                    },
                ],
            },
            {
                "pattern": _IQ[16],
                "header": _QY[2],
                "query": _NCT[2],
                "ruleset": [
                    {
                        "pattern": "query timed out",
                        "result": {"vendor": "Microsoft", "product": "Windows DNS", "version": "2000"},
                    },
                    {
                        "pattern": _IQ[4],
                        "header": _QY[8],
                        "query": _NCT[8],
                        "ruleset": [
                            {
                                "pattern": _IQ[17],
                                "header": _QY[4],
                                "query": _NCT[4],
                                "ruleset": [
                                    {
                                        "pattern": _IQ[18],
                                        "result": {"vendor": "ISC", "product": "BIND", "version": "9.7.2"},
                                    },
                                    {
                                        "pattern": _IQ[19],
                                        "result": {"vendor": "ISC", "product": "BIND", "version": "9.6.3 -- 9.7.3"},
                                    },
                                    {"pattern": ".+", "state": "q0r3q1r3r16q2r4q8r17q4r?"},
                                ],
                            },
                            {
                                "pattern": _IQ[20],
                                "header": _QY[4],
                                "query": _NCT[4],
                                "ruleset": [
                                    {
                                        "pattern": _IQ[19],
                                        "result": {"vendor": "ISC", "product": "BIND", "version": "9.5.2 -- 9.7.1"},
                                    },
                                    {
                                        "pattern": _IQ[18],
                                        "header": _QY[9],
                                        "query": _NCT[9],
                                        "ruleset": [
                                            {
                                                "pattern": _IQ[21],
                                                "result": {"vendor": "ISC", "product": "BIND", "version": "9.6.0 OR 9.4.0 -- 9.5.1"},
                                            },
                                            {
                                                "pattern": _IQ[22],
                                                "result": {"vendor": "ISC", "product": "BIND", "version": "9.4.0 -- 9.5.1"},
                                            },
                                            {"pattern": ".+", "state": "q0r3q1r3r16q2r4q8r17r20q4r18q9r?"},
                                        ],
                                    },
                                ],
                            },
                        ],
                    },
                ],
            },
        ],
    },
    {
        "pattern": _IQ[23],
        "header": _QY[0],
        "query": _NCT[0],
        "ruleset": [
            {
                "pattern": _IQ[24],
                "header": _QY[10],
                "query": _NCT[10],
                "ruleset": [
                    {
                        "pattern": _IQ[26],
                        "result": {"vendor": "NLnetLabs", "product": "Unbound", "version": "1.3.0 -- 1.4.0"},
                    },
                    {
                        "pattern": _IQ[27],
                        "header": _QY[11],
                        "query": _NCT[11],
                        "ruleset": [
                            {
                                "pattern": "header section incomplete",
                                "result": {"vendor": "NLnetLabs", "product": "Unbound", "version": "1.4.1 -- 1.4.9"},
                            },
                            {
                                "pattern": _IQ[19],
                                "result": {"vendor": "NLnetLabs", "product": "Unbound", "version": "1.4.10 -- 1.6.0"},
                            },
                            {"pattern": ".+", "state": "q0r3r23q10r25q11r?"},
                        ],
                    },
                ],
            },
            {
                "pattern": _IQ[25],
                "header": _QY[10],
                "query": _NCT[10],
                "ruleset": [
                    {
                        "pattern": _IQ[28],
                        "result": {"vendor": "NLnetLabs", "product": "Unbound", "version": "1.7.0 -- 1.9.6"},
                    },
                ],
            },
        ],
    },
]

_OLD_RULESET = [
    {
        "pattern": _IQ_OLD[89],
        "result": {"vendor": "Simon Kelley", "product": "dnsmasq", "version": ""},
        "qv": "version.bind",
    },
    {
        "pattern": ".+",
        "header": _QY_OLD[0],
        "query": ". IN A",
        "ruleset": [
            {
                "pattern": "query timed out",
                "header": _QY_OLD[0],
                "query": "com. IN A",
                "ruleset": [
                    {
                        "pattern": "query timed out",
                        "header": _QY_OLD[7],
                        "query": ". CH A",
                        "ruleset": [
                            {
                                "pattern": "query timed out",
                                "header": _QY_OLD[6],
                                "query": ". IN A",
                                "ruleset": [
                                    {
                                        "pattern": _IQ_OLD[38],
                                        "result": {"vendor": "Digital Lumber", "product": "Oak DNS", "version": ""},
                                        "qv": "version.oak",
                                    },
                                    {"pattern": "query timed out", "result": "TIMEOUT"},
                                    {"pattern": ".+", "state": "q0tq0tq7tq6r?"},
                                ],
                            },
                            {"pattern": _IQ_OLD[35], "result": {"vendor": "XBILL", "product": "jnamed (dnsjava)", "version": ""}},
                            {"pattern": _IQ_OLD[36], "result": {"vendor": "Men & Mice", "product": "QuickDNS for MacOS Classic", "version": ""}},
                            {"pattern": _IQ_OLD[37], "result": {"vendor": "unknown", "product": "NonSequitur DNS", "version": ""}},
                            {"pattern": ".+", "state": "q0tq0tq7r?"},
                        ],
                    },
                    {"pattern": _IQ_OLD[35], "result": {"vendor": "eNom", "product": "eNom DNS", "version": ""}},
                    {"pattern": ".+", "state": "q0tq0r?"},
                ],
            },
            {
                "pattern": _IQ_OLD[0],
                "header": _QY_OLD[1],
                "query": "jjjjjjjjjjjj IN A",
                "ruleset": [
                    {"pattern": _IQ_OLD[12], "result": {"vendor": "ISC", "product": "BIND", "version": "8.4.1-p1"}, "qv": "version.bind"},
                    {"pattern": _IQ_OLD[13], "result": {"vendor": "ISC", "product": "BIND", "version": "8 plus root server modifications"}, "qv": "version.bind"},
                    {"pattern": _IQ_OLD[15], "result": {"vendor": "Cisco", "product": "CNR", "version": ""}},
                    {
                        "pattern": _IQ_OLD[16],
                        "header": _QY_OLD[2],
                        "query": "hostname.bind CH TXT",
                        "ruleset": [
                            {"pattern": _IQ_OLD[58], "result": {"vendor": "ISC", "product": "BIND", "version": "8.3.0-RC1 -- 8.4.4"}, "qv": "version.bind"},
                            {"pattern": _IQ_OLD[50], "result": {"vendor": "ISC", "product": "BIND", "version": "8.3.0-RC1 -- 8.4.4"}, "qv": "version.bind"},
                            {"pattern": _IQ_OLD[48], "result": {"vendor": "ISC", "product": "BIND", "version": "8.2.2-P3 -- 8.3.0-T2A"}, "qv": "version.bind"},
                            {"pattern": ".+", "state": "q0r0q1r16q2r?"},
                        ],
                    },
                    {"pattern": ".+", "state": "q0r0q1r?"},
                ],
            },
            {
                "pattern": _IQ_OLD[1],
                "header": _QY_OLD[2],
                "query": ". IN IXFR",
                "ruleset": [
                    {"pattern": _IQ_OLD[31], "result": {"vendor": "Microsoft", "product": "Windows DNS", "version": "2000"}},
                    {"pattern": _IQ_OLD[32], "result": {"vendor": "Microsoft", "product": "Windows DNS", "version": "NT4"}},
                    {"pattern": _IQ_OLD[50], "result": {"vendor": "Microsoft", "product": "Windows DNS", "version": "2003"}},
                    {"pattern": ".+", "state": "q0r1q2r?"},
                ],
            },
            {
                "pattern": _IQ_OLD[2],
                "header": _QY_OLD[1],
                "ruleset": [
                    {"pattern": _IQ_OLD[11], "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.3rc1 -- 9.4.0a4"}, "qv": "version.bind"},
                    {
                        "pattern": _IQ_OLD[12],
                        "header": _QY_OLD[3],
                        "ruleset": [
                            {
                                "pattern": _IQ_OLD[25],
                                "header": _QY_OLD[6],
                                "ruleset": [
                                    {"pattern": _IQ_OLD[33], "result": {"vendor": "bboy", "product": "MyDNS", "version": ""}},
                                    {
                                        "pattern": _IQ_OLD[34],
                                        "header": _QY_OLD[2],
                                        "query": "012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.0123456789012345678901234567890123456789012345678901234567890. IN A",
                                        "ruleset": [
                                            {"pattern": _IQ_OLD[47], "result": {"vendor": "NLnetLabs", "product": "NSD", "version": "1.0.3 -- 1.2.1"}, "qv": "version.server"},
                                            {
                                                "pattern": _IQ_OLD[48],
                                                "header": _QY_OLD[2],
                                                "query": "hostname.bind CH TXT",
                                                "ruleset": [
                                                    {"pattern": _IQ_OLD[50], "result": {"vendor": "NLnetLabs", "product": "NSD", "version": "1.2.2"}, "qv": "version.server"},
                                                    {
                                                        "pattern": _IQ_OLD[51],
                                                        "header": _QY_OLD[8],
                                                        "query": ". IN A",
                                                        "ruleset": [
                                                            {"pattern": _IQ_OLD[93], "result": {"vendor": "NLnetLabs", "product": "NSD", "version": "1.2.3 -- 2.1.2"}, "qv": "version.server"},
                                                            {"pattern": _IQ_OLD[48], "result": {"vendor": "NLnetLabs", "product": "NSD", "version": "2.1.3"}, "qv": "version.server"},
                                                            {"pattern": ".+", "state": "q0r2q1r12q3r25q6r34q2r48q2r51q8r?"},
                                                        ],
                                                    },
                                                    {"pattern": ".+", "state": "q0r2q1r12q3r25q6r34q2r48q2r?"},
                                                ],
                                            },
                                            {
                                                "pattern": _IQ_OLD[49],
                                                "header": _QY_OLD[2],
                                                "query": "hostname.bind CH TXT",
                                                "ruleset": [
                                                    {"pattern": _IQ_OLD[50], "result": {"vendor": "NLnetLabs", "product": "NSD", "version": "1.2.2 [root]"}, "qv": "version.server"},
                                                    {"pattern": _IQ_OLD[51], "result": {"vendor": "NLnetLabs", "product": "NSD", "version": "1.2.3 [root]"}, "qv": "version.server"},
                                                    {"pattern": ".+", "state": "q0r2q1r12q3r25q6r34q2r49q2r?"},
                                                ],
                                            },
                                            {"pattern": _IQ_OLD[53], "result": {"vendor": "NLnetLabs", "product": "NSD", "version": "1.0.2"}, "qv": "version.server"},
                                            {"pattern": ".+", "state": "q0r2q1r12q3r25q6r34q2a?"},
                                        ],
                                    },
                                    {"pattern": ".+", "state": "q0r2q1r12q3r25q6r?"},
                                ],
                            },
                            {"pattern": _IQ_OLD[26], "result": {"vendor": "VeriSign", "product": "ATLAS", "version": ""}},
                            {"pattern": ".+", "state": "q0r2q1r12q3r?"},
                        ],
                    },
                    {
                        "pattern": _IQ_OLD[15],
                        "header": _QY_OLD[6],
                        "ruleset": [
                            {"pattern": _IQ_OLD[45], "result": {"vendor": "Nominum", "product": "ANS", "version": ""}, "qv": "version.bind"},
                            {"pattern": _IQ_OLD[65], "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.3rc1 -- 9.4.0a4"}, "qv": "version.bind"},
                            {
                                "pattern": _IQ_OLD[46],
                                "header": _QY_OLD[7],
                                "ruleset": [
                                    {"pattern": _IQ_OLD[56], "result": {"vendor": "ISC", "product": "BIND", "version": "9.0.0b5 -- 9.0.1"}, "qv": "version.bind"},
                                    {"pattern": _IQ_OLD[57], "result": {"vendor": "ISC", "product": "BIND", "version": "9.1.0 -- 9.1.3"}, "qv": "version.bind"},
                                    {"pattern": ".+", "state": "q0r2q1r15q6r46q7r?"},
                                ],
                            },
                            {"pattern": ".+", "state": "q0r2q1r15q6r?"},
                        ],
                    },
                    {
                        "pattern": _IQ_OLD[16],
                        "header": _QY_OLD[4],
                        "ruleset": [
                            {"pattern": _IQ_OLD[29], "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.0a1 -- 9.2.0rc3"}, "qv": "version.bind"},
                            {
                                "pattern": _IQ_OLD[30],
                                "header": _QY_OLD[0],
                                "query": ". A CLASS0",
                                "ruleset": [
                                    {"pattern": _IQ_OLD[2], "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.0rc7 -- 9.2.2-P3"}, "qv": "version.bind"},
                                    {"pattern": _IQ_OLD[0], "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.0rc4 -- 9.2.0rc6"}, "qv": "version.bind"},
                                    {"pattern": ".+", "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.0rc4 -- 9.2.2-P3"}, "qv": "version.bind"},
                                ],
                            },
                            {"pattern": ".+", "state": "q0r2q1r16q4r?"},
                        ],
                    },
                    {"pattern": ".+", "state": "q0r2q1r?"},
                ],
            },
            {
                "pattern": _IQ_OLD[3],
                "header": _QY_OLD[1],
                "ruleset": [
                    {
                        "pattern": "query timed out",
                        "header": _QY_OLD[5],
                        "ruleset": [
                            {"pattern": _IQ_OLD[3], "result": {"vendor": "sourceforge", "product": "Dents", "version": ""}, "qv": "version.bind"},
                            {"pattern": _IQ_OLD[81], "result": {"vendor": "Microsoft", "product": "Windows DNS", "version": "2003"}},
                            {"pattern": _IQ_OLD[91], "result": {"vendor": "Microsoft", "product": "Windows DNS", "version": "2003"}},
                            {"pattern": ".+", "state": "q0r3q1tq5r?"},
                        ],
                    },
                    {"pattern": _IQ_OLD[14], "result": {"vendor": "UltraDNS", "product": "", "version": "v2.7.0.2 -- 2.7.3"}, "qv": "version.bind"},
                    {
                        "pattern": _IQ_OLD[13],
                        "header": _QY_OLD[5],
                        "ruleset": [
                            {"pattern": _IQ_OLD[39], "result": {"vendor": "pliant", "product": "DNS Server", "version": ""}},
                            {"pattern": _IQ_OLD[7], "result": {"vendor": "JHSOFT", "product": "simple DNS plus", "version": ""}},
                            {
                                "pattern": _IQ_OLD[71],
                                "header": _QY_OLD[6],
                                "ruleset": [
                                    {"pattern": _IQ_OLD[41], "result": {"vendor": "Netnumber", "product": "ENUM server", "version": ""}},
                                    {"pattern": _IQ_OLD[85], "result": {"vendor": "Raiden", "product": "DNSD", "version": ""}},
                                ],
                            },
                            {"pattern": ".+", "state": "q0r3q1r13q5r?"},
                        ],
                    },
                    {"pattern": ".+", "state": "q0r3q1r?"},
                ],
            },
            {
                "pattern": _IQ_OLD[4],
                "header": _QY_OLD[1],
                "query": "jjjjjjjjjjjj IN A",
                "ruleset": [
                    {"pattern": _IQ_OLD[17], "result": {"vendor": "ISC", "product": "BIND", "version": "9.0.0b5 -- 9.0.1 [recursion enabled]"}, "qv": "version.bind"},
                    {
                        "pattern": _IQ_OLD[18],
                        "header": _QY_OLD[5],
                        "query": ". IN A",
                        "ruleset": [
                            {"pattern": _IQ_OLD[27], "result": {"vendor": "ISC", "product": "BIND", "version": "4.9.3 -- 4.9.11"}, "qv": "version.bind"},
                            {"pattern": _IQ_OLD[28], "result": {"vendor": "ISC", "product": "BIND", "version": "4.8 -- 4.8.3"}},
                            {"pattern": ".+", "state": "q0r4q1r18q5r?"},
                        ],
                    },
                    {"pattern": _IQ_OLD[19], "result": {"vendor": "ISC", "product": "BIND", "version": "8.2.1 [recursion enabled]"}, "qv": "version.bind"},
                    {
                        "pattern": _IQ_OLD[20],
                        "header": _QY_OLD[3],
                        "query": ". IN A",
                        "ruleset": [
                            {"pattern": _IQ_OLD[42], "result": {"vendor": "ISC", "product": "BIND", "version": "8.1-REL -- 8.2.1-T4B [recursion enabled]"}, "qv": "version.bind"},
                            {"pattern": ".+", "state": "q0r4q1r20q3r?"},
                        ],
                    },
                    {
                        "pattern": _IQ_OLD[21],
                        "header": _QY_OLD[2],
                        "query": "hostname.bind CH TXT",
                        "ruleset": [
                            {"pattern": _IQ_OLD[60], "result": {"vendor": "ISC", "product": "BIND", "version": "8.3.0-RC1 -- 8.4.4 [recursion enabled]"}, "qv": "version.bind"},
                            {
                                "pattern": _IQ_OLD[59],
                                "header": _QY_OLD[7],
                                "query": ". IN A",
                                "ruleset": [
                                    {"pattern": _IQ_OLD[68], "result": {"vendor": "ISC", "product": "BIND", "version": "8.1-REL -- 8.2.1-T4B [recursion enabled]"}, "qv": "version.bind"},
                                    {"pattern": _IQ_OLD[69], "result": {"vendor": "ISC", "product": "BIND", "version": "8.2.2-P3 -- 8.3.0-T2A [recursion enabled]"}, "qv": "version.bind"},
                                    {"pattern": "connection failed", "result": {"vendor": "Runtop", "product": "dsl/cable", "version": ""}},
                                    {"pattern": ".+", "state": "q0r4q1r21q2r59q7r?"},
                                ],
                            },
                            {"pattern": _IQ_OLD[58], "result": {"vendor": "ISC", "product": "BIND", "version": "8.3.0-RC1 -- 8.4.4 [recursion local]"}, "qv": "version.bind"},
                            {"pattern": _IQ_OLD[50], "result": {"vendor": "ISC", "product": "BIND", "version": "8.3.0-RC1 -- 8.4.4 [recursion local]"}, "qv": "version.bind"},
                            {"pattern": _IQ_OLD[61], "result": {"vendor": "ISC", "product": "BIND", "version": "8.3.0-RC1 -- 8.4.4 [recursion local]"}, "qv": "version.bind"},
                            {"pattern": _IQ_OLD[48], "result": {"vendor": "ISC", "product": "BIND", "version": "8.2.2-P3 -- 8.3.0-T2A [recursion local]"}, "qv": "version.bind"},
                            {"pattern": ".+", "state": "q0r4q1r21q2r?"},
                        ],
                    },
                    {"pattern": ".+", "state": "q0r4q1r?"},
                ],
            },
            {
                "pattern": _IQ_OLD[5],
                "header": _QY_OLD[1],
                "ruleset": [
                    {"pattern": _IQ_OLD[11], "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.3rc1 -- 9.4.0a4", "option": "recursion enabled,split view"}, "qv": "version.bind"},
                    {"pattern": _IQ_OLD[17], "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.3rc1 -- 9.4.0a4 [recursion enabled]"}, "qv": "version.bind"},
                    {
                        "pattern": _IQ_OLD[18],
                        "header": _QY_OLD[5],
                        "ruleset": [
                            {
                                "pattern": _IQ_OLD[5],
                                "header": _QY_OLD[7],
                                "query": ". IN A",
                                "ruleset": [
                                    {"pattern": _IQ_OLD[84], "result": {"vendor": "Nominum", "product": "CNS", "version": ""}, "qv": "version.bind"},
                                    {"pattern": _IQ_OLD[59], "result": {"vendor": "Mikrotik", "product": "dsl/cable", "version": ""}},
                                    {"pattern": _IQ_OLD[82], "result": {"vendor": "Mikrotik", "product": "dsl/cable", "version": ""}},
                                    {"pattern": ".+", "state": "q0r5q1r18q5r5q7r?"},
                                ],
                            },
                            {"pattern": _IQ_OLD[64], "result": "unknown, smells like old BIND 4"},
                            {"pattern": ".+", "state": "q0r5q1r18q5r?"},
                        ],
                    },
                    {
                        "pattern": _IQ_OLD[20],
                        "header": _QY_OLD[7],
                        "ruleset": [
                            {"pattern": _IQ_OLD[54], "result": {"vendor": "ISC", "product": "BIND", "version": "9.0.0b5 -- 9.0.1 [recursion enabled]"}, "qv": "version.bind"},
                            {"pattern": _IQ_OLD[55], "result": {"vendor": "ISC", "product": "BIND", "version": "9.1.0 -- 9.1.3 [recursion enabled]"}, "qv": "version.bind"},
                            {"pattern": _IQ_OLD[63], "result": {"vendor": "ISC", "product": "BIND", "version": "4.9.3 -- 4.9.11 [recursion enabled]"}, "qv": "version.bind"},
                            {"pattern": _IQ_OLD[61], "result": {"vendor": "ISC", "product": "BIND", "version": "9.0.0b5 -- 9.1.3 [recursion local]"}, "qv": "version.bind"},
                            {"pattern": ".+", "state": "q0r5q1r20q7r?"},
                        ],
                    },
                    {
                        "pattern": _IQ_OLD[21],
                        "header": _QY_OLD[4],
                        "ruleset": [
                            {"pattern": "query timed out", "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.0a1 -- 9.2.2-P3 [recursion enabled]"}, "qv": "version.bind"},
                            {"pattern": _IQ_OLD[29], "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.0a1 -- 9.2.0rc3 [recursion enabled]"}, "qv": "version.bind"},
                            {
                                "pattern": _IQ_OLD[61],
                                "header": _QY_OLD[0],
                                "query": ". A CLASS0",
                                "ruleset": [
                                    {"pattern": _IQ_OLD[2], "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.0rc7 -- 9.2.2-P3 [recursion enabled]"}, "qv": "version.bind"},
                                    {"pattern": _IQ_OLD[0], "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.0rc4 -- 9.2.0rc6 [recursion enabled]"}, "qv": "version.bind"},
                                    {"pattern": ".+", "result": {"vendor": "ISC", "product": "BIND", "version": "9.2.0rc4 -- 9.2.2-P3 [recursion enabled]"}, "qv": "version.bind"},
                                ],
                            },
                            {"pattern": ".+", "state": "q0r5q1r21q4r?"},
                        ],
                    },
                    {"pattern": ".+", "state": "q0r5q1r?"},
                ],
            },
            {
                "pattern": _IQ_OLD[6],
                "header": _QY_OLD[1],
                "ruleset": [
                    {"pattern": _IQ_OLD[15], "result": {"vendor": "incognito", "product": "DNS commander", "version": "v2.3.1.1 -- 4.0.5.1"}, "qv": "version.bind"},
                    {
                        "pattern": _IQ_OLD[19],
                        "header": _QY_OLD[3],
                        "ruleset": [
                            {"pattern": _IQ_OLD[66], "result": {"vendor": "vermicelli", "product": "totd", "version": ""}},
                            {"pattern": _IQ_OLD[67], "result": {"vendor": "JHSOFT", "product": "simple DNS plus", "version": "[recursion enabled]"}},
                            {"pattern": ".+", "state": "q0r6q1r19q3r?"},
                        ],
                    },
                    {"pattern": ".+", "state": "q0r6q1r?"},
                ],
            },
            {
                "pattern": _IQ_OLD[7],
                "header": _QY_OLD[1],
                "ruleset": [
                    {
                        "pattern": _IQ_OLD[22],
                        "header": _QY_OLD[3],
                        "ruleset": [
                            {"pattern": _IQ_OLD[97], "result": {"vendor": "PowerDNS", "product": "PowerDNS", "version": "2.9.4 -- 2.9.19"}, "qv": "version.bind"},
                            {"pattern": _IQ_OLD[98], "result": {"vendor": "Stanford", "product": "lbnamed", "version": "1.0.0 -- 2.3.2"}},
                            {"pattern": ".+", "state": "q0r7q1r22q3r?"},
                        ],
                    },
                    {"pattern": _IQ_OLD[24], "result": {"vendor": "PowerDNS", "product": "PowerDNS", "version": "2.8 -- 2.9.3"}, "qv": "version.bind"},
                    {"pattern": ".+", "state": "q0r7q1r?"},
                ],
            },
            {
                "pattern": _IQ_OLD[8],
                "header": _QY_OLD[1],
                "ruleset": [
                    {
                        "pattern": _IQ_OLD[23],
                        "header": _QY_OLD[2],
                        "query": ". CH A",
                        "ruleset": [
                            {"pattern": "query timed out", "result": {"vendor": "DJ Bernstein", "product": "TinyDNS", "version": "1.04"}},
                            {"pattern": _IQ_OLD[32], "result": {"vendor": "DJ Bernstein", "product": "TinyDNS", "version": "1.05"}},
                            {"pattern": ".+", "state": "q0r8q1r23q2r?"},
                        ],
                    },
                    {"pattern": ".+", "state": "q0r8q1r?"},
                ],
            },
            {
                "pattern": _IQ_OLD[9],
                "header": _QY_OLD[1],
                "ruleset": [
                    {"pattern": _IQ_OLD[9], "result": {"vendor": "Sam Trenholme", "product": "MaraDNS", "version": ""}, "qv": "erre-con-erre-cigarro.maradns.org"},
                    {"pattern": ".+", "state": "q0r9q1r?"},
                ],
            },
            {"pattern": _IQ_OLD[10], "result": {"vendor": "Microsoft", "product": "?", "version": ""}},
            {"pattern": _IQ_OLD[26], "result": {"vendor": "Meilof Veeningen", "product": "Posadis", "version": ""}},
            {
                "pattern": _IQ_OLD[43],
                "header": _QY_OLD[6],
                "ruleset": [
                    {"pattern": _IQ_OLD[34], "result": {"vendor": "Paul Rombouts", "product": "pdnsd", "version": ""}},
                    {"pattern": _IQ_OLD[75], "result": {"vendor": "antirez", "product": "Yaku-NS", "version": ""}},
                    {"pattern": ".+", "state": "q0r43q6r?"},
                ],
            },
            {"pattern": _IQ_OLD[44], "result": {"vendor": "cpan", "product": "Net::DNS Nameserver", "version": ""}, "qv": "version.bind"},
            {"pattern": _IQ_OLD[52], "result": {"vendor": "NLnetLabs", "product": "NSD", "version": "1.0 alpha"}},
            {
                "pattern": _IQ_OLD[55],
                "header": _QY_OLD[3],
                "ruleset": [
                    {"pattern": _IQ_OLD[94], "result": {"vendor": "robtex", "product": "Viking DNS module", "version": ""}},
                    {"pattern": _IQ_OLD[95], "result": {"vendor": "cisco", "product": "dns resolver/server", "version": ""}},
                    {"pattern": ".+", "state": "q0r55q3r?"},
                ],
            },
            {"pattern": _IQ_OLD[59], "result": {"vendor": "Max Feoktistov", "product": "small HTTP server [recursion enabled]", "version": ""}},
            {"pattern": _IQ_OLD[60], "result": {"vendor": "Axis", "product": "video server", "version": ""}},
            {
                "pattern": _IQ_OLD[62],
                "header": _QY_OLD[7],
                "query": "1.0.0.127.in-addr.arpa. IN PTR",
                "ruleset": [
                    {"pattern": _IQ_OLD[62], "result": {"vendor": "Michael Tokarev", "product": "rbldnsd", "version": ""}, "qv": "version.bind"},
                    {"pattern": _IQ_OLD[79], "result": {"vendor": "4D", "product": "WebSTAR", "version": ""}},
                    {"pattern": _IQ_OLD[83], "result": {"vendor": "Netopia", "product": "dsl/cable", "version": ""}},
                    {"pattern": _IQ_OLD[90], "result": {"vendor": "TZO", "product": "Tzolkin DNS", "version": ""}},
                    {"pattern": "query timed out", "result": {"vendor": "Netopia", "product": "dsl/cable", "version": ""}},
                    {"pattern": ".+", "state": "q0r62q7r?"},
                ],
            },
            {"pattern": _IQ_OLD[70], "result": {"vendor": "Yutaka Sato", "product": "DeleGate DNS", "version": ""}},
            {"pattern": _IQ_OLD[72], "result": {"vendor": "", "product": "sheerdns", "version": ""}},
            {"pattern": _IQ_OLD[73], "result": {"vendor": "Matthew Pratt", "product": "dproxy", "version": ""}},
            {"pattern": _IQ_OLD[74], "result": {"vendor": "Brad Garcia", "product": "dnrd", "version": ""}},
            {"pattern": _IQ_OLD[76], "result": {"vendor": "Sourceforge", "product": "JDNSS", "version": ""}},
            {"pattern": _IQ_OLD[77], "result": {"vendor": "Dan Kaminsky", "product": "nomde DNS tunnel", "version": ""}},
            {"pattern": _IQ_OLD[78], "result": {"vendor": "Max Feoktistov", "product": "small HTTP server", "version": ""}},
            {"pattern": _IQ_OLD[79], "result": {"vendor": "robtex", "product": "Viking DNS module", "version": ""}},
            {"pattern": _IQ_OLD[80], "result": {"vendor": "Fasthosts", "product": "Envisage DNS server", "version": ""}},
            {"pattern": _IQ_OLD[81], "result": {"vendor": "WinGate", "product": "Wingate DNS", "version": ""}},
            {"pattern": _IQ_OLD[82], "result": {"vendor": "Ascenvision", "product": "SwiftDNS", "version": ""}},
            {"pattern": _IQ_OLD[86], "result": {"vendor": "Nortel Networks", "product": "Instant Internet", "version": ""}},
            {"pattern": _IQ_OLD[87], "result": {"vendor": "ATOS", "product": "Stargate ADSL", "version": ""}},
            {"pattern": _IQ_OLD[88], "result": {"vendor": "3Com", "product": "Office Connect Remote", "version": ""}},
            {"pattern": _IQ_OLD[89], "result": {"vendor": "Alteon", "product": "ACEswitch", "version": ""}},
            {"pattern": _IQ_OLD[90], "result": {"vendor": "javaprofessionals", "product": "javadns/jdns", "version": ""}},
            {"pattern": _IQ_OLD[92], "result": {"vendor": "Beehive", "product": "CoDoNS", "version": ""}},
            {"pattern": _IQ_OLD[96], "result": {"vendor": "Beevihe", "product": "AAAAAA", "version": ""}, "qv": "version.bind"},
            {"pattern": _IQ_OLD[100], "result": {"vendor": "ValidStream", "product": "ValidDNS", "version": ""}},
            {"pattern": _IQ_OLD[101], "result": {"vendor": "ValidStream", "product": "ValidDNS", "version": ""}},
            {"pattern": ".+", "state": "q0r?"},
        ],
    },
]

_VERSION_LENGTH = 40


class DNSFingerprint:
    """Fingerprint DNS servers by sending crafted probes and analysing responses."""

    VERSION = "0.13.0"

    def __init__(self, source=None, timeout=5, retry=1, forcetcp=False,
                 debug=False, qversion=False, qchaos=False):
        self.source = source
        self.timeout = timeout
        self.retry = retry
        self.forcetcp = forcetcp
        self.debug = debug
        self.qversion = qversion
        self.qchaos = qchaos
        self._cache = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fingerprint(self, target, port=53):
        return self.hash(target, port)

    def hash(self, target, port=53):
        return self._init(target, port)

    def string(self, target, port=53):
        result = self.hash(target, port)

        if "error" in result:
            return result["error"]

        parts = []
        if "result" in result:
            parts.append(result["result"])
        else:
            if result.get("vendor"):
                parts.append(result["vendor"])
            if result.get("product"):
                parts.append(result["product"])
            if result.get("version"):
                parts.append(result["version"])
            if result.get("option"):
                parts.append(f"[{result['option']}]")
            if result.get("ruleset"):
                parts.append(f"[{result['ruleset']} Rules]")

        if result.get("vstring"):
            parts.append(result["vstring"])

        if self.debug and result.get("state"):
            parts.append(result["state"])

        return " ".join(parts) if parts else "Unknown"

    def query_version(self, server, port, ident="version.bind"):
        """Query the server for its version string via CH TXT."""
        try:
            q = dns.message.make_query(ident, dns.rdatatype.TXT, dns.rdataclass.CH)
            if self.forcetcp:
                response = dns.query.tcp(q, server, port=port, timeout=self.timeout,
                                         source=self.source)
            else:
                response = dns.query.udp(q, server, port=port, timeout=self.timeout,
                                         source=self.source)

            if response and response.answer:
                texts = []
                for rrset in response.answer:
                    for rdata in rrset:
                        if hasattr(rdata, "strings"):
                            for s in rdata.strings:
                                texts.append(s.decode("utf-8", errors="replace"))
                        else:
                            texts.append(rdata.to_text().strip('"'))
                if texts:
                    result = f' id: "{" ".join(texts)}"'
                    if len(result) > _VERSION_LENGTH:
                        result = result[:_VERSION_LENGTH] + "..."
                    return result

            return " id unavailable"
        except Exception as e:
            return f" id unavailable ({e})"

    # ------------------------------------------------------------------
    # Internal fingerprinting engine
    # ------------------------------------------------------------------

    def _init(self, target, port):
        """Try new fingerprint ruleset, fall back to old for legacy servers."""
        self._cache.clear()

        result = self._process(target, port, _QY[0], _NCT[0], _RULESET, "New")
        if result.get("product") or result.get("result"):
            return result

        # Old ruleset – ignores the recursion-desired bit (backwards compat)
        return self._process(
            target, port,
            _QY_OLD[2], ". IN MAILB",
            _OLD_RULESET, "Old",
            ignore_recurse=True,
        )

    def _process(self, target, port, header_str, query_str,
                 ruleset, ruleset_name, ignore_recurse=False):
        """Recursively walk the ruleset, issuing probes as required."""
        if self.debug:
            print(f"==> PROCESS {target}:{port} [{header_str}] [{query_str}]")

        response, error_str = self._probe(
            target, port, header_str, query_str, ignore_recurse=ignore_recurse
        )

        if response is not None:
            fp_id = self._header_to_fp(response)
        else:
            fp_id = error_str

        if self.debug:
            print(f'==> id="{fp_id}"')

        for rule in ruleset:
            pattern = rule.get("pattern", "")
            try:
                if not re.fullmatch(pattern, fp_id):
                    continue
            except re.error:
                continue

            # --- Terminal: result ---
            if "result" in rule:
                ret = {}
                ver = " "
                if self.qversion and rule.get("qv"):
                    ver = self.query_version(target, port, rule["qv"])
                if self.qchaos:
                    ver = self.query_version(target, port, "version.bind")
                if ver and ver.strip():
                    ret["vstring"] = ver

                res = rule["result"]
                if isinstance(res, dict):
                    ret["vendor"] = res.get("vendor", "")
                    ret["product"] = res.get("product", "")
                    ret["version"] = res.get("version", "")
                    if res.get("option"):
                        ret["option"] = res["option"]
                    if res.get("state"):
                        ret["state"] = res["state"]
                    ret["ruleset"] = ruleset_name
                else:
                    ret["result"] = res
                return ret

            # --- Terminal: no-match state ---
            if "state" in rule:
                ver = " "
                if self.qversion:
                    ver = self.query_version(target, port, "hostname.bind")
                ret = {"error": "No match found", "state": rule["state"], "id": fp_id}
                if ver and ver.strip():
                    ret["vstring"] = ver
                return ret

            # --- Recurse with updated header/query ---
            next_query = rule.get("query", query_str)
            if "header" in rule and "ruleset" in rule:
                return self._process(
                    target, port,
                    rule["header"], next_query,
                    rule["ruleset"], ruleset_name,
                    ignore_recurse=ignore_recurse,
                )

        return {}

    def _probe(self, target, port, header_str, query_str, ignore_recurse=False):
        """Send a crafted DNS probe; returns (dns.message.Message | None, error_str)."""
        cache_key = f"{target}:{port}/{header_str}.{query_str}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            wire = self._build_packet(header_str, query_str)
        except Exception as e:
            return None, f"build error: {e}"

        error = "query timed out"
        for _ in range(max(1, self.retry)):
            try:
                response = self._send_recv_raw(wire, target, port)
                if response is not None:
                    pair = (response, "")
                    self._cache[cache_key] = pair
                    return pair
            except _ShortHeaderError:
                pair = (None, "header section incomplete")
                self._cache[cache_key] = pair
                return pair
            except dns.exception.Timeout:
                error = "query timed out"
            except OSError as exc:
                msg = str(exc).lower()
                if "refused" in msg:
                    error = "connection refused"
                else:
                    error = "connection failed"
            except Exception as exc:
                low = str(exc).lower()
                if "timed out" in low or "timeout" in low:
                    error = "query timed out"
                elif "refused" in low:
                    error = "connection refused"
                else:
                    error = "connection failed"

        return None, error

    def _send_recv_raw(self, wire, target, port):
        """Send raw wire bytes and return a parsed dns.message.Message."""
        family = socket.AF_INET6 if ":" in target else socket.AF_INET

        if self.forcetcp:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if self.source:
                    sock.bind((self.source, 0))
                sock.connect((target, port))
                length_prefix = struct.pack("!H", len(wire))
                sock.sendall(length_prefix + wire)
                raw_len = self._recv_n(sock, 2)
                if not raw_len:
                    return None
                (resp_len,) = struct.unpack("!H", raw_len)
                raw = self._recv_n(sock, resp_len)
        else:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                if self.source:
                    sock.bind((self.source, 0))
                sock.sendto(wire, (target, port))
                raw, _ = sock.recvfrom(65535)

        if not raw:
            return None

        try:
            return dns.message.from_wire(raw)
        except dns.message.ShortHeader:
            raise _ShortHeaderError()
        except Exception:
            return None

    @staticmethod
    def _recv_n(sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    @staticmethod
    def _build_packet(header_str, query_str):
        """Return raw DNS wire bytes for a fingerprinting probe."""
        parts = header_str.split(",")
        if len(parts) != 13:
            raise ValueError(f"Bad header string: {header_str!r}")

        qr_val = int(parts[0])
        opcode_str = parts[1]
        aa, tc, rd, ra, ad, cd = (int(x) for x in parts[2:8])
        rcode_str = parts[8]
        qdcount, ancount, nscount, arcount = (int(x) for x in parts[9:13])

        msg = dns.message.Message()

        flags = 0
        if qr_val: flags |= dns.flags.QR
        if aa:     flags |= dns.flags.AA
        if tc:     flags |= dns.flags.TC
        if rd:     flags |= dns.flags.RD
        if ra:     flags |= dns.flags.RA
        if ad:     flags |= dns.flags.AD
        if cd:     flags |= dns.flags.CD

        try:
            flags |= dns.opcode.to_flags(dns.opcode.from_text(opcode_str))
        except Exception:
            pass

        msg.flags = flags

        try:
            msg.set_rcode(dns.rcode.from_text(rcode_str))
        except Exception:
            pass

        # Parse "name [class] type" query string
        q_parts = query_str.split()
        qname = dns.name.from_text(q_parts[0])
        if len(q_parts) == 3:
            try:
                rdcls = dns.rdataclass.from_text(q_parts[1])
            except Exception:
                rdcls = dns.rdataclass.IN
            try:
                rdtype = dns.rdatatype.from_text(q_parts[2])
            except Exception:
                rdtype = dns.rdatatype.A
        elif len(q_parts) == 2:
            rdcls = dns.rdataclass.IN
            try:
                rdtype = dns.rdatatype.from_text(q_parts[1])
            except Exception:
                rdtype = dns.rdatatype.A
        else:
            rdcls, rdtype = dns.rdataclass.IN, dns.rdatatype.A

        msg.question.append(dns.rrset.RRset(qname, rdcls, rdtype))

        wire = bytearray(msg.to_wire())
        # Deliberately override the counts – fingerprinting exploits header mismatches
        struct.pack_into("!HHHH", wire, 4, qdcount, ancount, nscount, arcount)
        return bytes(wire)

    @staticmethod
    def _header_to_fp(msg):
        """Convert a DNS response header to a fingerprint string."""
        qr = 1 if (msg.flags & dns.flags.QR) else 0
        aa = 1 if (msg.flags & dns.flags.AA) else 0
        tc = 1 if (msg.flags & dns.flags.TC) else 0
        rd = 1 if (msg.flags & dns.flags.RD) else 0
        ra = 1 if (msg.flags & dns.flags.RA) else 0
        ad = 1 if (msg.flags & dns.flags.AD) else 0
        cd = 1 if (msg.flags & dns.flags.CD) else 0

        try:
            opcode = dns.opcode.to_text(msg.opcode())
        except Exception:
            opcode = "QUERY"

        try:
            rcode = dns.rcode.to_text(msg.rcode())
        except Exception:
            rcode = "NOERROR"

        return (
            f"{qr},{opcode},{aa},{tc},{rd},{ra},{ad},{cd},{rcode},"
            f"{len(msg.question)},{len(msg.answer)},"
            f"{len(msg.authority)},{len(msg.additional)}"
        )


class _ShortHeaderError(Exception):
    """Raised when a DNS response contains an incomplete header."""
