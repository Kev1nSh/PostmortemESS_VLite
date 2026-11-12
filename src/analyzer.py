# src/analyzer.py
# Analyzes a parsed email dict from parser.py.
# Checks: headers, SPF/DKIM/DMARC, IP reputation, URLs, attachments.
# All external calls send only hashes, IP addresses, URLs, or sender email – never raw content.
# Stateless: no data is stored or retained after analyze() returns.
# Returns structured result dict with verdict: MOST LIKELY SAFE / MOST LIKELY UNSAFE / FURTHER ANALYSIS REQUIRED
#
# External threat sources:
#   Spamhaus ZEN        – IP blocklist via DNSBL              (no key required)
#   Spamhaus DBL        – domain blocklist via DNSBL           (no key required)
#   URLhaus             – malicious URL database               (ABUSE_CH_API_KEY)
#   MalwareBazaar       – malware hash database (SHA256)       (ABUSE_CH_API_KEY)
#   ThreatFox           – IOC database: IPs, domains, hashes  (ABUSE_CH_API_KEY)
#   AbuseIPDB           – IP abuse confidence score 0-100     (ABUSEIPDB_API_KEY)
#   VirusTotal          – URL/file/IP — 70+ AV engines        (VIRUSTOTAL_API_KEY)
#   OpenLookup          – sender email reputation            (OPENLOOKUP_API_KEY)
#   Google SafeBrowsing – URL phishing/malware check           (GOOGLE_SAFE_BROWSING_KEY)
#
# All env vars are optional — sources are skipped gracefully if unset.
# ABUSE_CH_API_KEY covers URLhaus, MalwareBazaar and ThreatFox (same key from auth.abuse.ch).

import os
import re
import hashlib
from wsgiref import headers
from lark.tools import flags
import requests
import dns.resolver
import time
from email.utils import parseaddr
from src.logger import get_logger

try:
    import dkim as _dkim
    _DKIM_AVAILABLE = True
except ImportError:
    _DKIM_AVAILABLE = False

logger = get_logger(__name__)

_TIMEOUT  = 5
_MAX_URLS = 15

# AbuseIPDB thresholds (0–100 confidence score)
_ABUSEIPDB_MALICIOUS  = 80   # → OSÄKERT
_ABUSEIPDB_SUSPICIOUS = 25   # → YTTERLIGARE ANALYS BEHÖVS

DANGEROUS_EXTENSIONS = frozenset({
    '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse', '.hta',
    '.msi', '.scr', '.pif', '.com', '.lnk', '.wsf', '.jar', '.dll',
    '.docm', '.xlsm', '.pptm', '.iso', '.img', '.vhd',
})

DKIM_SELECTORS = [
    'default', 'mail', 'google', 'k1', 'k2',
    'selector1', 'selector2', 'dkim', 'email', 's1', 's2',
]

_PRIVATE_IP = re.compile(
    r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.)'
)

_MIME_MAGIC = {
    b'\x4d\x5a':         'application/x-msdownload',
    b'\x7fELF':          'application/x-elf',
    b'%PDF':             'application/pdf',
    b'PK\x03\x04':       'application/zip',
    b'PK\x05\x06':       'application/zip',
    b'Rar!':             'application/x-rar-compressed',
    b'\x1f\x8b':         'application/gzip',
    b'#!':               'application/x-sh',
    b'\xca\xfe\xba\xbe': 'application/java',
}

_SPAM_TOOLS = frozenset({'ratware', 'mass mailer', 'advance mailer', 'dark mailer'})

# Known legitimate CDN/infrastructure domains — skip DBL check
_DBL_WHITELIST = frozenset({
    'fonts.googleapis.com',
    'fonts.gstatic.com',
    'ajax.googleapis.com',
    'apis.google.com',
    'cdnjs.cloudflare.com',
    'cdn.jsdelivr.net',
    'unpkg.com',
    'stackpath.bootstrapcdn.com',
    'maxcdn.bootstrapcdn.com',
    'code.jquery.com',
})

# ── Internal helpers ──────────────────────────────────────────────────────────

def _extract_domain(field: str) -> str:
    _, addr = parseaddr(field)
    if '@' in addr:
        return addr.split('@')[-1].lower().strip()
    # Fallback when parseaddr is defeated by malformed From headers:
    # grab the domain directly from the first @domain pattern.
    m = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', field)
    if m:
        return m.group(1).lower().strip().rstrip('>')
    return ''


def _extract_sender_ip(received_list: list) -> str:
    if not received_list:
        return ''
    # Search all hops, oldest first (last in list = closest to sender).
    # Match IPv4 regardless of [brackets], (parens) or bare form.
    # Skip private/internal IPs — we want the public originating address.
    ip_re = re.compile(r'(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])')
    for hop in reversed(received_list):
        for m in ip_re.finditer(hop):
            ip = m.group(1)
            if not _PRIVATE_IP.match(ip):
                return ip
    return ''


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _detect_mime(data: bytes) -> str | None:
    for magic, mime in _MIME_MAGIC.items():
        if data[:len(magic)] == magic:
            return mime
    return None


def _resolve_txt(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=_TIMEOUT)
        return [b''.join(r.strings).decode('utf-8', errors='replace') for r in answers]
    except Exception:
        return []


def _lookup_spf(domain: str) -> str | None:
    for r in _resolve_txt(domain):
        if r.startswith('v=spf1'):
            return r
    return None


def _lookup_dmarc(domain: str) -> str | None:
    for r in _resolve_txt(f'_dmarc.{domain}'):
        if r.startswith('v=DMARC1'):
            return r
    return None


def _lookup_dkim_record(domain: str, selectors: list = None) -> tuple[str | None, str]:
    if selectors is None:
        selectors = DKIM_SELECTORS
    for selector in selectors:
        for r in _resolve_txt(f'{selector}._domainkey.{domain}'):
            if 'v=DKIM1' in r or 'p=' in r:
                return r, selector
    return None, ''


def _verify_dkim(raw_bytes: bytes) -> bool | None:
    if not _DKIM_AVAILABLE or not raw_bytes:
        return None
    try:
        return bool(_dkim.verify(raw_bytes))
    except Exception:
        return None


def _extract_dkim_selector_from_bytes(raw_bytes: bytes) -> str:
    """
    Reads the actual DKIM selector used in the email from its DKIM-Signature header.
    DKIM-Signature contains s=<selector> which tells us exactly which DNS record to look up.
    Without this, we only try guesses and miss selectors like '20230601' (Gmail).
    """
    if not raw_bytes:
        return ''
    import re as _re
    # Find s= tag inside DKIM-Signature header value
    # Simple approach: find DKIM-Signature then look for s= within next 500 bytes
    idx = raw_bytes.find(b'DKIM-Signature:')
    if idx == -1:
        return ''
    chunk = raw_bytes[idx:idx+500]
    sel_match = _re.search(b'[; \t]s=([a-zA-Z0-9_.-]+)', chunk)
    if not sel_match:
        return ''
    return sel_match.group(1).decode('ascii', errors='replace')

def _dnsbl(host: str, zone: str) -> bool:

    query = f'{host}.{zone}'
    try:
        answer = dns.resolver.resolve(query, 'A', lifetime=_TIMEOUT)
        listed = any(answer)
        logger.debug('DNSBL lookup: host=%s zone=%s result=%s answer=%s', host, zone,'LISTED' if listed else 'NOT LISTED', [str(record) for record in answer])
        
    except dns.resolver.NXDOMAIN:
        logger.debug('DNSBL lookup: host=%s zone=%s result=NXDOMAIN', host, zone)
        return False
    except Exception:
        logger.debug('DNSBL lookup: host=%s zone=%s result=NO ANSWER', host, zone)
        return False


def _urlhaus(url: str) -> bool:
    key = os.environ.get('ABUSE_CH_API_KEY', '')
    headers = {'Auth-Key': key} if key else {}
    try:
        r = requests.post(
            'https://urlhaus-api.abuse.ch/v1/url/',
            data={'url': url},
            headers=headers,
            timeout=_TIMEOUT,
        )
        if r.status_code != 200:
            return False
        data = r.json()
        status = data.get('query_status', '')
        return status in ('ok', 'is_url')
    except Exception:
        return False


def _malwarebazaar(sha256_hash: str) -> bool:
    key = os.environ.get('ABUSE_CH_API_KEY', '') or os.environ.get('MALWAREBAZAAR_API_KEY', '')
    headers = {'Auth-Key': key} if key else {}
    try:
        r = requests.post(
            'https://mb-api.abuse.ch/api/v1/',
            data={'query': 'get_info', 'hash': sha256_hash},
            headers=headers,
            timeout=_TIMEOUT,
        )
        return r.status_code == 200 and r.json().get('query_status') == 'ok'
    except Exception:
        return False

def _threatfox(ioc: str) -> bool:
    """
    Checks any IOC (IP, domain, URL, file hash) against ThreatFox.
    ThreatFox tracks malware C2 servers, ransomware infrastructure,
    and botnet addresses. Requires ABUSE_CH_API_KEY.
    Returns True if the IOC is a known malicious indicator.
    """
    if not ioc:
        return False
    key = os.environ.get('ABUSE_CH_API_KEY', '')
    headers = {'Auth-Key': key} if key else {}
    try:
        r = requests.post(
            'https://threatfox-api.abuse.ch/api/v1/',
            json={'query': 'search_ioc', 'search_term': ioc},
            headers=headers,
            timeout=_TIMEOUT,
        )
        return r.status_code == 200 and r.json().get('query_status') == 'ok'
    except Exception:
        return False


def _abuseipdb(ip: str) -> int:
    """
    Returns AbuseIPDB confidence score (0–100) for an IP address.
    0   = never reported / clean
    100 = confirmed malicious with high confidence
    -1  = key not configured or request failed (treated as unknown)

    Requires ABUSEIPDB_API_KEY environment variable.
    Free tier: 1,000 checks/day. Register at https://www.abuseipdb.com/register
    """
    key = os.environ.get('ABUSEIPDB_API_KEY', '')
    if not key:
        return -1
    try:
        r = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': key, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': '90'},
            timeout=_TIMEOUT,
        )
        if r.status_code == 200:
            return int(r.json().get('data', {}).get('abuseConfidenceScore', 0))
        return -1
    except Exception:
        return -1




def _virustotal_url(url: str) -> dict | None:
    """
    Checks a URL against VirusTotal — scans against 70+ engines simultaneously.
    Returns {'malicious': int, 'suspicious': int, 'total': int} or None on error.

    Free tier: 4 requests/minute, 500/day.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """
    key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    if not key or not url:
        return None
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        r = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers={'x-apikey': key},
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            return {'malicious': 0, 'suspicious': 0, 'total': 0, 'note': 'not in database'}
        if r.status_code == 429:
            logger.warning('VirusTotal rate limit hit – skipping remaining URL checks')
            return None
        if r.status_code != 200:
            return None
        stats = r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return {
            'malicious':  stats.get('malicious',  0),
            'suspicious': stats.get('suspicious', 0),
            'total':      sum(stats.values()),
            'note':       '',
        }
    except Exception as e:
        logger.debug(f'VirusTotal URL check failed: {e}')
        return None


def _virustotal_hash(sha256_hash: str) -> dict | None:
    """
    Checks a file hash against VirusTotal.
    Returns {'malicious': int, 'suspicious': int, 'total': int} or None on error.
    Sends only the SHA256 hash — raw file bytes never leave the container.
    """
    key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    if not key or not sha256_hash:
        return None
    try:
        r = requests.get(
            f'https://www.virustotal.com/api/v3/files/{sha256_hash}',
            headers={'x-apikey': key},
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            return {'malicious': 0, 'suspicious': 0, 'total': 0, 'note': 'not in database'}
        if r.status_code == 429:
            logger.warning('VirusTotal rate limit hit')
            return None
        if r.status_code != 200:
            return None
        stats = r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return {
            'malicious':  stats.get('malicious',  0),
            'suspicious': stats.get('suspicious', 0),
            'total':      sum(stats.values()),
            'note':       '',
        }
    except Exception as e:
        logger.debug(f'VirusTotal hash check failed: {e}')
        return None


def _virustotal_ip(ip: str) -> dict | None:
    """
    Checks an IP address against VirusTotal.
    Returns {'malicious': int, 'suspicious': int, 'total': int} or None on error.
    """
    key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    if not key or not ip:
        return None
    try:
        r = requests.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
            headers={'x-apikey': key},
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            return {'malicious': 0, 'suspicious': 0, 'total': 0, 'note': 'not in database'}
        if r.status_code == 429:
            logger.warning('VirusTotal rate limit hit')
            return None
        if r.status_code != 200:
            return None
        stats = r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return {
            'malicious':  stats.get('malicious',  0),
            'suspicious': stats.get('suspicious', 0),
            'total':      sum(stats.values()),
            'note':       '',
        }
    except Exception as e:
        logger.debug(f'VirusTotal IP check failed: {e}')
        return None

def _openlookup_email(email_address: str) -> dict:
    """
    Check sender email risk with OpenLookup.

    OpenLookup is currently used as an additional evidence source.
    It does not directly determine the final verdict.
    """
    if not email_address or '@' not in email_address:
        return {
            'available': False,
            'reason': 'no_sender_email'
        }
    key = os.environ.get('OPENLOOKUP_API_KEY', '')
    if not key:
        return {
            'available': False,
            'reason': 'not_configured'
        }

    try:
        r = requests.post(
            'https://openlookup.io/api/v1/email/check',
            headers={
                'Authorization': f'Bearer {key}',
                'Content-Type': 'application/json',
            },
            json={
                'email': email_address
            },
            timeout=_TIMEOUT,
        )
        if r.status_code != 200:
            logger.debug(
                f'OpenLookup returned HTTP {r.status_code}'
            )
            return {
                'available': False,
                'reason': f'http_{r.status_code}'
            }
        data = r.json()

        return {
            'available': True,
            'risk_score': data.get('risk_score'),
            'classification': data.get('classification'),
            'recommendation': data.get('recommendation'),

            'signals': {
                'syntax_valid': data.get('syntax_valid'),
                'domain_exists': data.get('domain_exists'),
                'mx_found': data.get('mx_found'),
                'disposable': data.get('disposable'),
                'role_account': data.get('role_account'),
                'free_provider': data.get('free_provider'),
            },
        }
    except requests.RequestException as e:
        logger.debug(
            f'OpenLookup request failed: {e}'
        )
        return {
            'available': False,
            'reason': 'request_failed'
        }
    except (ValueError, TypeError) as e:
        logger.debug(
            f'OpenLookup response parsing failed: {e}'
        )
        return {
            'available': False,
            'reason': 'invalid_response'
        }

def _google_safe_browsing(urls: list) -> dict:
    """
    Checks a list of URLs against Google Safe Browsing (Lookup API v4).
    Covers: malware, phishing (SOCIAL_ENGINEERING), unwanted software, harmful apps.

    Up to 500 URLs per call — all URLs checked in a single request.
    Returns a dict mapping url → threat_type for any matches.
    Returns empty dict if clean or API not configured.

    GDPR note: actual URL strings are sent to Google (not hashed).
    URLs are generally not personal data; this is acceptable for security analysis.

    Env: GOOGLE_SAFE_BROWSING_KEY (required — free Google Cloud API key)
    Get key: console.cloud.google.com → Enable Safe Browsing API → Create credentials
    Free: 10,000 requests/day
    """
    key = os.environ.get('GOOGLE_SAFE_BROWSING_KEY', '')
    if not key or not urls:
        return {}
    try:
        r = requests.post(
            f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}',
            json={
                'client': {
                    'clientId':      'postmortemcli',
                    'clientVersion': '0.2.1',
                },
                'threatInfo': {
                    'threatTypes':      [
                        'MALWARE',
                        'SOCIAL_ENGINEERING',        # phishing
                        'UNWANTED_SOFTWARE',
                        'POTENTIALLY_HARMFUL_APPLICATION',
                    ],
                    'platformTypes':    ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries':    [{'url': u} for u in urls],
                },
            },
            timeout=_TIMEOUT,
        )
        if r.status_code == 400:
            logger.warning(f'Google Safe Browsing bad request: {r.text[:200]}')
            return {}
        if r.status_code != 200:
            return {}
        matches = r.json().get('matches', [])
        # Map url → threat type (most severe if multiple)
        results = {}
        for match in matches:
            url         = match.get('threat', {}).get('url', '')
            threat_type = match.get('threatType', 'UNKNOWN')
            results[url] = threat_type
        return results
    except Exception as e:
        logger.debug(f'Google Safe Browsing check failed: {e}')
        return {}

# ── Check functions ───────────────────────────────────────────────────────────

def check_headers(headers: dict) -> dict:
    from_domain     = _extract_domain(headers.get('from', ''))
    reply_domain    = _extract_domain(headers.get('reply_to', ''))
    return_path_dom = _extract_domain(headers.get('return_path', ''))
    sender_ip       = _extract_sender_ip(headers.get('received', []))

    flags = []

    reply_mismatch = bool(reply_domain and from_domain and reply_domain != from_domain)
    if reply_mismatch:
        flags.append(f'Reply-To domain ({reply_domain}) differs from From ({from_domain})')

    return_path_mismatch = bool(return_path_dom and from_domain and return_path_dom != from_domain)
    if return_path_mismatch:
        flags.append(f'Return-Path domain ({return_path_dom}) differs from From ({from_domain})')

    mid_mismatch = False
    mid = headers.get('message_id', '')
    if mid and from_domain:
        m = re.search(r'@([^>]+)>', mid)
        if m:
            mid_domain = m.group(1).lower().strip()
            # Accept subdomains: mail.gmail.com is valid for gmail.com
            is_subdomain = mid_domain.endswith('.' + from_domain)
            if mid_domain != from_domain and not is_subdomain:
                mid_mismatch = True
                flags.append(
                    f'Message-ID domain ({mid_domain}) differs from From ({from_domain})'
                )

    no_received = not headers.get('received')
    if no_received:
        flags.append('No Received headers – possible direct injection')

    x_mailer = headers.get('x_mailer', '').lower()
    if x_mailer and any(t in x_mailer for t in _SPAM_TOOLS):
        flags.append(f'Suspicious X-Mailer: {headers["x_mailer"]}')

    # ── OpenLookup ────────────────────────────────────────────────────────────

    from_addr = headers.get('from', '')
    _, from_email = parseaddr(from_addr)

    if not from_email:
        match = re.search(
            r'<\s*([^<>\s]+@[^<>\s]+)\s*>',
            from_addr
        )
        if match:
            from_email = match.group(1)

    openlookup = _openlookup_email(from_email)

    if openlookup.get('available'):
        risk_score = openlookup.get('risk_score')
        recommendation = openlookup.get('recommendation')
        signals = openlookup.get('signals') or {}

        if recommendation == 'block':
            flags.append(
                f'Sender address {from_email} has high OpenLookup email risk '
                f'(risk score: {risk_score})'
            )
        elif recommendation == 'review':
            flags.append(
                f'Sender address {from_email} has medium OpenLookup email risk '
                f'(risk score: {risk_score})'
            )
        if signals.get('disposable'):
            flags.append(
                f'Sender address {from_email} is a disposable/throwaway address '
                f'(OpenLookup)'
            )

    logger.info(
        f'Header check: {len(flags)} flag(s) | '
        f'from={from_domain} | '
        f'ip={sender_ip} | '
        f'openlookup='
        f'{openlookup.get("risk_score") if openlookup.get("available") else openlookup.get("reason", "unavailable")}' #
)
    return {
        'from_domain':          from_domain,
        'reply_to_domain':      reply_domain,
        'return_path_domain':   return_path_dom,
        'sender_ip':            sender_ip,
        'received_hops':        len(headers.get('received', [])),
        'reply_mismatch':       reply_mismatch,
        'return_path_mismatch': return_path_mismatch,
        'mid_mismatch':         mid_mismatch,
        'no_received':          no_received,
        'openlookup':            openlookup,
        'from_email':            from_email,
        'flags':                flags,
    }


def check_authentication(domain: str, raw_bytes: bytes = b'') -> dict:
    if not domain:
        return {
            'domain': '',
            'spf':   {'record': None, 'result': 'missing'},
            'dmarc': {'record': None, 'result': 'missing', 'policy': 'none'},
            'dkim':  {'record': None, 'result': 'missing', 'selector': '',
                      'signature_present': False, 'signature_valid': None},
            'flags': ['Could not extract sender domain – skipping auth checks'],
        }

    spf_record           = _lookup_spf(domain)
    dmarc_record         = _lookup_dmarc(domain)

    # Try selector extracted from actual email first, then fall back to common selectors
    email_selector = _extract_dkim_selector_from_bytes(raw_bytes)
    if email_selector and email_selector not in DKIM_SELECTORS:
        dkim_selectors_to_try = [email_selector] + DKIM_SELECTORS
    elif email_selector:
        dkim_selectors_to_try = [email_selector] + [s for s in DKIM_SELECTORS if s != email_selector]
    else:
        dkim_selectors_to_try = DKIM_SELECTORS

    dkim_record, sel     = _lookup_dkim_record(domain, dkim_selectors_to_try)

    dmarc_policy = 'none'
    if dmarc_record:
        m = re.search(r'\bp=(\w+)', dmarc_record)
        if m:
            dmarc_policy = m.group(1)

    sig_present = b'DKIM-Signature' in raw_bytes if raw_bytes else False
    sig_valid   = _verify_dkim(raw_bytes) if sig_present else None

    flags = []
    if not spf_record:
        flags.append(f'No SPF record for {domain}')
    if not dmarc_record:
        flags.append(f'No DMARC record for {domain}')
    if not dkim_record:
        flags.append(f'No DKIM DNS record for {domain} (tried: {", ".join(DKIM_SELECTORS)})')
    if sig_present and sig_valid is False:
        flags.append('DKIM signature present but verification failed')
    if dmarc_record and dmarc_policy == 'none':
        flags.append(f'DMARC policy is "none" for {domain} – monitoring only, no enforcement')

    logger.info(
        f'Auth: domain={domain} | '
        f'spf={"found" if spf_record else "missing"} | '
        f'dmarc={"found" if dmarc_record else "missing"}(p={dmarc_policy}) | '
        f'dkim_dns={"found" if dkim_record else "missing"} | '
        f'sig_present={sig_present} sig_valid={sig_valid}'
    )

    return {
        'domain': domain,
        'spf':   {'record': spf_record,   'result': 'found' if spf_record   else 'missing'},
        'dmarc': {'record': dmarc_record, 'result': 'found' if dmarc_record else 'missing',
                  'policy': dmarc_policy},
        'dkim':  {'record': dkim_record,  'result': 'found' if dkim_record  else 'missing',
                  'selector': sel, 'signature_present': sig_present, 'signature_valid': sig_valid},
        'flags': flags,
    }


def check_reputation(ip: str) -> dict:
    """
    Checks sender IP against:
      - Spamhaus ZEN DNSBL  (binary listed/clean)
      - ThreatFox            (known C2/malware infrastructure)
      - AbuseIPDB            (0–100 confidence score, requires API key)
    """
    empty = {
        'ip':              ip,
        'spamhaus_zen':    False,
        'threatfox_ip':    False,
        'abuseipdb_score': -1,
        'virustotal_ip':   None,
        'flags':           [],
    }

    if not ip or _PRIVATE_IP.match(ip):
        return empty

    flags = []

    reversed_ip = '.'.join(reversed(ip.split('.')))
    on_zen      = _dnsbl(reversed_ip, 'zen.spamhaus.org')
    if on_zen:
        flags.append(f'Sender IP {ip} listed on Spamhaus ZEN')

    tf_hit = _threatfox(ip)
    if tf_hit:
        flags.append(f'Sender IP {ip} found in ThreatFox (known C2/malware infrastructure)')

    vt_ip = _virustotal_ip(ip)
    if vt_ip is not None and vt_ip['malicious'] > 0:
        flags.append(
            f'Sender IP {ip} flagged by {vt_ip["malicious"]}/{vt_ip["total"]} '
            f'VirusTotal engines'
        )

    score = _abuseipdb(ip)
    if score >= _ABUSEIPDB_MALICIOUS:
        flags.append(f'Sender IP {ip} has AbuseIPDB confidence score {score}/100')
    elif score >= _ABUSEIPDB_SUSPICIOUS:
        flags.append(f'Sender IP {ip} has elevated AbuseIPDB score {score}/100')

    logger.info(
        f'Reputation: ip={ip} | '
        f'zen={"LISTED" if on_zen else "clean"} | '
        f'threatfox={"HIT" if tf_hit else "clean"} | '
        f'abuseipdb={score if score != -1 else "not configured"}'
    )

    return {
        'ip':              ip,
        'spamhaus_zen':    on_zen,
        'threatfox_ip':    tf_hit,
        'abuseipdb_score': score,
        'virustotal_ip':   vt_ip,
        'flags':           flags,
    }


def check_urls(urls: list) -> dict:
    """
    Checks each URL against:
      - URLhaus       (malware distribution URLs)
      - Spamhaus DBL  (domain blocklist)
      - ThreatFox     (malicious domain infrastructure)
    """
    results = []
    flags   = []
    targets = list(dict.fromkeys(urls))[:_MAX_URLS]

    vt_delay = float(os.environ.get('VIRUSTOTAL_RATE_DELAY', '0'))

    # Google Safe Browsing — single bulk call for all URLs at once
    gsb_results = _google_safe_browsing(targets)
    if gsb_results:
        logger.info(f'Google Safe Browsing: {len(gsb_results)} threat(s) found in {len(targets)} URLs')

    # Track flagged domains to avoid duplicate flags for same domain
    _flagged_dbl_domains      = set()
    _flagged_threatfox_domains = set()

    for url in targets:
        entry = {
            'url':              url,
            'urlhaus':          False,
            'spamhaus_dbl':     False,
            'threatfox_domain': False,
            'virustotal':       None,
            'google_safebrowsing': None,
        }

        # GSB result already computed in bulk above
        gsb_threat = gsb_results.get(url)
        if gsb_threat:
            entry['google_safebrowsing'] = gsb_threat
            threat_label = {
                'MALWARE':                         'malware',
                'SOCIAL_ENGINEERING':              'phishing/social engineering',
                'UNWANTED_SOFTWARE':               'unwanted software',
                'POTENTIALLY_HARMFUL_APPLICATION': 'potentially harmful app',
            }.get(gsb_threat, gsb_threat)
            flags.append(f'URL flagged by Google Safe Browsing as {threat_label}: {url}')

        if _urlhaus(url):
            entry['urlhaus'] = True
            flags.append(f'URL found in URLhaus: {url}')

        m = re.search(r'https?://([^/?\s]+)', url)
        if m:
            domain = m.group(1).lower().rstrip('.')

            if domain not in _DBL_WHITELIST and _dnsbl(domain, 'dbl.spamhaus.org'):
                entry['spamhaus_dbl'] = True
                if domain not in _flagged_dbl_domains:
                    flags.append(f'URL domain on Spamhaus DBL: {domain}')
                    _flagged_dbl_domains.add(domain)

            if _threatfox(domain):
                entry['threatfox_domain'] = True
                if domain not in _flagged_threatfox_domains:
                    flags.append(f'URL domain found in ThreatFox: {domain}')
                    _flagged_threatfox_domains.add(domain)

        vt = _virustotal_url(url)
        entry['virustotal'] = vt
        if vt is not None:
            if vt['malicious'] > 0:
                flags.append(
                    f'URL flagged by {vt["malicious"]}/{vt["total"]} VirusTotal engines: {url}'
                )
            elif vt['suspicious'] > 0:
                flags.append(
                    f'URL marked suspicious by {vt["suspicious"]}/{vt["total"]} VirusTotal engines: {url}'
                )
            if vt_delay > 0:
                time.sleep(vt_delay)

        results.append(entry)

    urlhaus_hits   = sum(1 for r in results if r['urlhaus'])
    dbl_hits       = sum(1 for r in results if r['spamhaus_dbl'])
    threatfox_hits = sum(1 for r in results if r['threatfox_domain'])
    vt_hits        = sum(1 for r in results if r['virustotal'] and r['virustotal']['malicious'] > 0)
    vt_suspicious  = sum(1 for r in results if r['virustotal'] and r['virustotal']['suspicious'] > 0 and (not r['virustotal']['malicious']))
    gsb_hits       = sum(1 for r in results if r['google_safebrowsing'])

    logger.info(
        f'URL check: {len(targets)}/{len(urls)} checked | '
        f'urlhaus={urlhaus_hits} | dbl={dbl_hits} | threatfox={threatfox_hits} | '
        f'gsb={gsb_hits} | vt_malicious={vt_hits} | vt_suspicious={vt_suspicious}'
    )

    return {
        'total':          len(urls),
        'checked':        len(targets),
        'results':        results,
        'urlhaus_hits':   urlhaus_hits,
        'dbl_hits':       dbl_hits,
        'threatfox_hits': threatfox_hits,
        'gsb_hits':       gsb_hits,
        'vt_hits':        vt_hits,
        'vt_suspicious':  vt_suspicious,
        'flags':          flags,
    }


def check_attachments(attachments: list) -> dict:
    """
    For each attachment:
      - SHA256 hash
      - MalwareBazaar hash lookup
      - ThreatFox hash lookup
      - Dangerous extension check
      - MIME magic byte vs declared content-type mismatch
    Only hashes are sent externally – raw bytes never leave the container.
    """
    results = []
    flags   = []

    for att in attachments:
        data     = att.get('data', b'')
        filename = att.get('filename', 'unknown')
        declared = att.get('content_type', '').lower()

        sha256_hash   = _sha256(data) if data else ''
        ext_match     = re.search(r'\.[a-zA-Z0-9]{1,10}$', filename)
        extension     = ext_match.group(0).lower() if ext_match else ''
        dangerous     = extension in DANGEROUS_EXTENSIONS
        detected_mime = _detect_mime(data[:8]) if data else None
        mime_mismatch = bool(
            detected_mime and
            detected_mime not in declared and
            declared not in detected_mime
        )
        mb_hit = _malwarebazaar(sha256_hash) if sha256_hash else False
        tf_hit = _threatfox(sha256_hash)     if sha256_hash else False
        vt_hit = _virustotal_hash(sha256_hash) if sha256_hash else None

        if mb_hit:
            flags.append(f'Attachment {filename} ({sha256_hash[:16]}…) found in MalwareBazaar')
        if tf_hit:
            flags.append(f'Attachment {filename} ({sha256_hash[:16]}…) found in ThreatFox')
        if vt_hit is not None and vt_hit['malicious'] > 0:
            flags.append(
                f'Attachment {filename} flagged by {vt_hit["malicious"]}/{vt_hit["total"]} '
                f'VirusTotal engines ({sha256_hash[:16]}…)'
            )
        if dangerous:
            flags.append(f'Dangerous attachment extension: {filename} ({extension})')
        if mime_mismatch:
            flags.append(
                f'MIME mismatch in {filename}: '
                f'declared={declared}, detected={detected_mime}'
            )

        results.append({
            'filename':      filename,
            'sha256':        sha256_hash,
            'extension':     extension,
            'declared_mime': declared,
            'detected_mime': detected_mime,
            'dangerous':     dangerous,
            'mime_mismatch': mime_mismatch,
            'malwarebazaar': mb_hit,
            'threatfox':     tf_hit,
            'virustotal':    vt_hit,
            'size':          att.get('size', 0),
        })

        logger.debug(
            f'Attachment: {filename} | sha256={sha256_hash[:16]}… | '
            f'mb={mb_hit} | tf={tf_hit} | '
            f'dangerous={dangerous} | mime_mismatch={mime_mismatch}'
        )

    mb_hits = sum(1 for r in results if r['malwarebazaar'])
    tf_hits = sum(1 for r in results if r['threatfox'])
    vt_hits = sum(1 for r in results if r['virustotal'] and r['virustotal']['malicious'] > 0)
    logger.info(
        f'Attachment check: {len(results)} file(s) | '
        f'mb_hits={mb_hits} | tf_hits={tf_hits} | vt_hits={vt_hits}'
    )

    return {
        'count':              len(results),
        'results':            results,
        'malwarebazaar_hits': mb_hits,
        'threatfox_hits':     tf_hits,
        'vt_hits':            vt_hits,
        'flags':              flags,
    }


# ── Verdict ───────────────────────────────────────────────────────────────────

def _calculate_verdict(
    header_f: dict,
    auth_f:   dict,
    rep_f:    dict,
    url_f:    dict,
    att_f:    dict,
) -> str:
    abuseipdb_score = rep_f.get('abuseipdb_score', -1)

    openlookup = header_f.get('openlookup') or {}
    openlookup_available = bool(openlookup.get('available'))
    openlookup_recommendation = (
        openlookup.get('recommendation')
        if openlookup_available
        else None
    )
    openlookup_signals = openlookup.get('signals') or {}

    spf = auth_f.get('spf') or {}
    dmarc = auth_f.get('dmarc') or {}   
    dkim = auth_f.get('dkim') or {}

    # ── VirusTotal hits ───────────────────────────────────────────────────────

    vt_ip = rep_f.get('virustotal_ip') or {}
    vt_ip_malicious  = vt_ip.get('malicious', 0) > 0
    vt_url_malicious  = url_f.get('vt_hits', 0) > 0
    vt_attachment_malicious  = att_f.get('vt_hits', 0) > 0
    vt_url_suspicious = url_f.get('vt_suspicious', 0) > 0

    # ────Strong threat probability indicators ────────────────────────────────────────────────────────────────────

    strong_malicious = any([
        rep_f.get('threatfox_ip', False),

        url_f.get('urlhaus_hits', 0) > 0,
        url_f.get('threatfox_hits', 0) > 0,
        url_f.get('gsb_hits', 0) > 0,

        att_f.get('malwarebazaar_hits', 0) > 0,
        att_f.get('threatfox_hits', 0) > 0,
    
        vt_ip_malicious,
        vt_url_malicious,
        vt_attachment_malicious,
        abuseipdb_score != -1 and abuseipdb_score >= _ABUSEIPDB_MALICIOUS,
    ])

    if strong_malicious:
        return 'MOST LIKELY UNSAFE'

    # ── Auth verification ───────────────────────────────────────────────────────
    # Missing records, auth fails and reputation/listing signals give risk indicator
    # Not enough to be definitive, but worth further analysis.
    
    missing_auth = sum([
        spf.get('result') == 'missing',
        dmarc.get('result') == 'missing',
        dkim.get('result') == 'missing',
    ])

    dkim_failed = (
        dkim.get('signature_present', False)
        and dkim.get('signature_valid') is False
    )
    
    # ── Suspicious / uncertain indicators ─────────────────────────────────────

    suspicious = any([
        missing_auth > 0,

        dmarc.get('policy', 'none') == 'none',
        dkim_failed,

        header_f.get('reply_mismatch', False),
        header_f.get('return_path_mismatch', False),
        header_f.get('mid_mismatch', False),
        header_f.get('no_received', False),

        openlookup_recommendation in ('block', 'review'),
        openlookup_signals.get('disposable', False),
        
        rep_f.get('spamhaus_zen', False),

        abuseipdb_score != -1 and abuseipdb_score >= _ABUSEIPDB_SUSPICIOUS,

        vt_url_suspicious,

        url_f.get('dbl_hits', 0) > 0,

        any(
            item.get('dangerous', False) 
            for item in att_f.get('results', [])
        ),
        any(
            item.get('mime_mismatch', False)
            for item in att_f.get('results', [])
        ),
    ])

    if suspicious:
        return 'FURTHER ANALYSIS REQUIRED'

    # ── Positive indicators ─────────────────────────────────────────────────────

    auth_positive = (
        spf.get('result') == 'pass'
        and dmarc.get('result') == 'pass'
        and dkim.get('signature_valid') is True
    )

    if auth_positive:
        return 'MOST LIKELY SAFE'

    # ── Default ───────────────────────────────────────────────────────────────

    return 'FURTHER ANALYSIS REQUIRED'


# ── Entry point ───────────────────────────────────────────────────────────────

def analyze(parsed: dict, raw_bytes: bytes = b'') -> dict:
    logger.info('Analysis started')

    headers         = parsed.get('headers', {})
    header_findings = check_headers(headers)
    auth_findings   = check_authentication(header_findings['from_domain'], raw_bytes)
    rep_findings    = check_reputation(header_findings['sender_ip'])
    url_findings    = check_urls(parsed.get('urls', []))
    att_findings    = check_attachments(parsed.get('attachments', []))

    verdict = _calculate_verdict(
        header_findings, auth_findings, rep_findings, url_findings, att_findings
    )

    all_flags = (
        header_findings['flags'] +
        auth_findings['flags']   +
        rep_findings['flags']    +
        url_findings['flags']    +
        att_findings['flags']
    )

    logger.info(f'Analysis complete: verdict={verdict} | flags={len(all_flags)}')

    return {
        'verdict':         verdict,
        'domain':          auth_findings['domain'],
        'sender_ip':       header_findings['sender_ip'],
        'header_findings': header_findings,
        'auth_findings':   auth_findings,
        'rep_findings':    rep_findings,
        'url_findings':    url_findings,
        'att_findings':    att_findings,
        'all_flags':       all_flags,
    }