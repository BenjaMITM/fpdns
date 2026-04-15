import re
import json
from pathlib import Path
import dns.resolver
import dns.rdatatype
import dns.rdataclass

class DNSFingerprint:
    """Fingerpint DNS servers"""

    VERSION = "0.13.0"

    def __init__(self, source=None, timeout=5, retry=1, forcetcp=False, debug=False, 
                 qversion=False, qchaos=False):
        # Initialize fingerprinter with options
        self.source = source
        self.timeout = timeout
        self.retry = retry
        self.forcetcp = forcetcp
        self.debug = debug
        self.qversion = qversion
        self.qchaos = qchaos
        self.ignore_recurse = False

        # Load fingerprint data
        self.ruleset = self._load_ruleset()

    def _load_ruleset(self):
        data_path = Path(__file__).parent.parent / 'data' / 'fingerprints.json'
        if data_path.exists():
            with open(data_path) as f:
                return json.load(f)
        return {}

    def fingerprint(self, target, port=53):
        return self.hash(target, port)

    def hash(self, target, port=53):
        try:
            result = self._probe_server(target, port)
            return result
        except Exception as e:
            return {'error': str(e)}

    def string(self, target, port=53):
        result = self.hash(target, port)

        if 'error' in result:
            return result['error']

        parts = []
        if 'result' in result:
            parts.append(result['result'])
        else:
            if 'vendor' in result:
                parts.append(result['vendor'])
            if 'product' in result:
                parts.append(result['product'])
            if 'version' in result:
                parts.append(result['version'])
            
        if 'vstring' in result:
            parts.append(result['vstring'])

        return ' '.join(parts) if parts else 'Unknown'

    def _probe_server(self, target, port):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [target]
            resolver.port = port
            resolver.lifetime = self.timeout
            if self.source:
                resolver.source = self.source

            # TODO: implement fingeprinting logic, for now use placeholder
            return {
                'vendor': 'Unknown',
                'product': 'Unknown',
                'version': 'Unknown',
            }
        except Exception as e:
            return {'error': str(e)}

    def query_version(self, server, port, ident="version.bind"):
        # Query the server for its version using CH TXT query
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            resolver.port = port
            resolver.lifetime = self.timeout
         
            answers = resolver.resolve(ident, dns.rdatatype.TXT, dns_class=dns.rdataclasss.CH)

            results = []
            for rdata in answers:
                for txt in rdata.strings:
                    results.append(txt.decode('utf-8', errors='ignore'))

            if results:
                return f' id: "{" ".join(results)}"'
            else:
                return ' id unavailable'
        except Exception as e:
            return f' id unavailable ({str(e)})'