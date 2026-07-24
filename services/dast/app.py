import os
import ssl
import json
import re
import socket
from urllib.parse import urlparse, urljoin
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

PASSIVE_TIMEOUT = 10
ACTIVE_TIMEOUT = 15
ACTIVE_MARKER = 'SENTINEL_PROBE_8f3a2b'

CWE_KB = {
    'missing_csp': {
        'cwe': 'CWE-693', 'owasp': 'A05:2021 - Security Misconfiguration',
        'name': 'Content Security Policy Missing', 'severity': 'medium',
        'what_template': 'The Content Security Policy (CSP) header is not set on responses from {endpoint}. This means no restrictions are placed on what resources the browser can load, scripts it can execute, or origins it can connect to.',
        'why_template': 'Without CSP, the application is more vulnerable to cross-site scripting (XSS) and data injection attacks. An attacker who finds any XSS vector can execute arbitrary JavaScript without CSP blocking the malicious resource.',
        'remediation': 'Add a Content-Security-Policy header with appropriate directives. Start with a restrictive policy and relax as needed. Example: "Content-Security-Policy: default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'"'
    },
    'missing_hsts': {
        'cwe': 'CWE-319', 'owasp': 'A02:2021 - Cryptographic Failures',
        'name': 'HSTS Not Enabled', 'severity': 'medium',
        'what_template': 'The Strict-Transport-Security (HSTS) header is not set on responses from {endpoint}. Browsers will not enforce HTTPS-only connections for this domain.',
        'why_template': 'Without HSTS, users who type the URL without https:// or follow old bookmarks may connect over plain HTTP, allowing an active network attacker to intercept or modify traffic via downgrade attacks.',
        'remediation': 'Add the header: "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload". Start with a short max-age for testing, then increase.'
    },
    'missing_xfo': {
        'cwe': 'CWE-1021', 'owasp': 'A05:2021 - Security Misconfiguration',
        'name': 'X-Frame-Options Missing', 'severity': 'medium',
        'what_template': 'Neither X-Frame-Options nor a CSP frame-ancestors directive is set on responses from {endpoint}. The page can be embedded in iframes on arbitrary third-party sites.',
        'why_template': 'This enables clickjacking attacks where an attacker overlays invisible iframes over legitimate UI elements, tricking users into performing unintended actions.',
        'remediation': 'Add "X-Frame-Options: DENY" or use CSP "frame-ancestors \'none\'" to prevent framing entirely. If embedding is needed, use "frame-ancestors \'self\'" with a specific allowlist.'
    },
    'insecure_cookies': {
        'cwe': 'CWE-614', 'owasp': 'A05:2021 - Security Misconfiguration',
        'name': 'Insecure Cookie Configuration', 'severity': 'medium',
        'what_template': 'Cookies set by {endpoint} are missing security flags: {missing_flags}. These cookies will be transmitted over unencrypted connections and/or accessible to client-side JavaScript.',
        'why_template': 'Cookies without HttpOnly can be stolen via XSS. Cookies without Secure can be intercepted on HTTP connections. Cookies without SameSite are vulnerable to CSRF attacks.',
        'remediation': 'Set all cookie flags: HttpOnly (prevents JavaScript access), Secure (HTTPS only), SameSite=Strict or Lax (prevents cross-site sending). Example: Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Lax'
    },
    'cors_misconfiguration': {
        'cwe': 'CWE-942', 'owasp': 'A05:2021 - Security Misconfiguration',
        'name': 'CORS Misconfiguration', 'severity': 'high',
        'what_template': 'The server at {endpoint} responds with Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true. This allows any origin to make credentialed cross-origin requests.',
        'why_template': 'An attacker can host a malicious page that makes authenticated requests to this application using the victim\'s cookies, reading sensitive data or performing actions on their behalf.',
        'remediation': 'Never use wildcard (*) with credentials. Instead, echo back the specific allowed origin: "Access-Control-Allow-Origin: https://yourdomain.com". Maintain an explicit allowlist of trusted origins.'
    },
    'error_disclosure': {
        'cwe': 'CWE-209', 'owasp': 'A04:2021 - Insecure Design',
        'name': 'Error Message Information Disclosure', 'severity': 'low',
        'what_template': 'The server at {endpoint} returns detailed error messages (stack traces, database errors, or framework debug pages) when given malformed input.',
        'why_template': 'Verbose error messages reveal internal implementation details: file paths, database schema, framework versions, and code structure. This information helps attackers craft more targeted exploits.',
        'remediation': 'Implement custom error handlers that return generic error messages. Log detailed errors server-side only. Disable debug mode in production. Use error monitoring tools instead of exposing errors to users.'
    },
    'server_banner_disclosure': {
        'cwe': 'CWE-200', 'owasp': 'A01:2021 - Broken Access Control',
        'name': 'Server Version Disclosure', 'severity': 'info',
        'what_template': 'The Server header at {endpoint} discloses version information: {banner}. This reveals the exact software and version running on the server.',
        'why_template': 'Attackers can use version information to look up known vulnerabilities for that specific software version, making exploitation faster and more targeted.',
        'remediation': 'Remove or obfuscate the Server header. In Apache: "ServerTokens Prod" and "ServerSignature Off". In Nginx: "server_tokens off". Do not expose version numbers in any response header.'
    },
    'exposed_metadata': {
        'cwe': 'CWE-538', 'owasp': 'A01:2021 - Broken Access Control',
        'name': 'Sensitive File/Path Exposed', 'severity': 'high',
        'what_template': 'A sensitive file is publicly accessible at {endpoint}: {file_detail}. This exposes configuration data, source control metadata, or environment variables.',
        'why_template': 'Exposed .git directories reveal the full source code history including credentials that may have been committed then removed. Exposed .env files contain secrets directly. Exposed robots.txt reveals hidden admin paths.',
        'remediation': 'Block access to sensitive paths at the web server level. For .git: "RedirectMatch 404 \\.git" in Apache or "location ~ /.git { deny all; }" in Nginx. For .env: serve from outside the web root or block access. Audit git history for leaked secrets.'
    },
    'open_redirect': {
        'cwe': 'CWE-601', 'owasp': 'A01:2021 - Broken Access Control',
        'name': 'Open Redirect Detected', 'severity': 'medium',
        'what_template': 'The endpoint {endpoint} accepts a redirect parameter that forwards users to an arbitrary external URL without validation.',
        'why_template': 'Open redirects are commonly used in phishing attacks: the attacker crafts a link that appears to go to the legitimate site but redirects to a malicious page, stealing credentials or delivering malware.',
        'remediation': 'Validate redirect targets against a strict allowlist of permitted domains. Never redirect to user-supplied URLs. Use relative paths for internal redirects. If external redirects are needed, show an interstitial page warning the user.'
    },
    'weak_tls': {
        'cwe': 'CWE-326', 'owasp': 'A02:2021 - Cryptographic Failures',
        'name': 'Weak TLS Configuration', 'severity': 'high',
        'what_template': 'The server at {endpoint} uses a weak or outdated TLS configuration: {tls_detail}.',
        'why_template': 'Weak TLS protocols (TLS 1.0, 1.1, SSLv3) and expired certificates mean that encrypted connections can be intercepted, decrypted, or are not properly authenticated, allowing man-in-the-middle attacks.',
        'remediation': 'Disable TLS 1.0 and 1.1. Use TLS 1.2 or 1.3 only. Obtain a valid certificate from a trusted CA and set up automated renewal. Use tools like Mozilla SSL Configuration Generator for recommended settings.'
    },
    'sqli_indicator': {
        'cwe': 'CWE-89', 'owasp': 'A03:2021 - Injection',
        'name': 'SQL Injection Indicator', 'severity': 'critical',
        'what_template': 'Active probing of {endpoint} with SQL-syntax payloads caused a behavioral change consistent with SQL injection: {probe_detail}.',
        'why_template': 'An attacker could inject arbitrary SQL queries to read, modify, or delete data, bypass authentication, or execute administrative operations on the database. SQL injection remains one of the most damaging web vulnerabilities.',
        'remediation': 'Use parameterized queries or prepared statements for all database interactions. Use an ORM that handles parameterization automatically. Validate and sanitize all user input. Apply principle of least privilege to database accounts.',
        'active': True
    },
    'xss_reflection': {
        'cwe': 'CWE-79', 'owasp': 'A03:2021 - Injection',
        'name': 'Reflected XSS Indicator', 'severity': 'high',
        'what_template': 'A benign probe marker injected into {endpoint} was reflected unescaped in the HTML response, indicating a reflected XSS vulnerability.',
        'why_template': 'An attacker could inject malicious JavaScript that executes in victims\' browsers, stealing session cookies, redirecting users, or performing actions on their behalf.',
        'remediation': 'Encode all output data context-appropriately (HTML entity, JavaScript, URL encoding). Use frameworks that auto-escape by default. Implement Content Security Policy. Never use innerHTML with user input.',
        'active': True
    },
    'idor_indicator': {
        'cwe': 'CWE-639', 'owasp': 'A01:2021 - Broken Access Control',
        'name': 'IDOR Indicator', 'severity': 'high',
        'what_template': 'Different ID parameter values sent to {endpoint} return distinct responses, suggesting that object-level access controls are not enforced.',
        'why_template': 'An attacker can enumerate or modify other users\' data by changing ID parameters, accessing records they are not authorized to see or modify.',
        'remediation': 'Implement proper authorization checks for every object access. Verify that the authenticated user owns or has permission to access the requested resource. Use indirect references (UUIDs) instead of sequential IDs where possible.',
        'active': True
    },
    'auth_bypass': {
        'cwe': 'CWE-287', 'owasp': 'A07:2021 - Identification and Authentication Failures',
        'name': 'Authentication Bypass Pattern', 'severity': 'critical',
        'what_template': 'The admin/privileged route at {endpoint} is accessible without authentication, returning sensitive content directly.',
        'why_template': 'An attacker can access administrative functions, modify system settings, view all user data, or perform privileged operations without any credentials.',
        'remediation': 'Enforce authentication on all privileged routes using middleware. Implement role-based access control (RBAC). Verify authorization at every endpoint, not just the UI layer. Use session tokens or JWTs with proper validation.',
        'active': True
    }
}


def _parse_endpoint(target_url, path=None, param=None, header=None):
    parsed = urlparse(target_url)
    endpoint = f"{parsed.scheme}://{parsed.netloc}"
    if path:
        endpoint += path
    parts = []
    if param:
        parts.append(f'parameter "{param}"')
    if header:
        parts.append(f'header "{header}"')
    return endpoint, parts


def _build_explanation(check_name, target_url, confidence, detection_source,
                       path=None, param=None, header=None, extra_detail=None):
    kb = CWE_KB.get(check_name)
    if not kb:
        return None

    endpoint, parts = _parse_endpoint(target_url, path, param, header)

    what = kb['what_template'].format(
        endpoint=endpoint,
        banner=extra_detail or '',
        file_detail=extra_detail or '',
        tls_detail=extra_detail or '',
        missing_flags=extra_detail or '',
        probe_detail=extra_detail or ''
    )

    why = kb['why_template']

    if parts:
        where = f"{endpoint} ({', '.join(parts)})"
    else:
        where = endpoint

    strength = 'high' if confidence >= 0.90 else ('medium' if confidence >= 0.70 else 'low')
    if strength == 'high':
        qualifier = 'exact behavioral match against known-vulnerable pattern'
    elif strength == 'medium':
        qualifier = 'behavior consistent with the issue but not confirmed'
    else:
        qualifier = 'indirect indicators suggest this issue may be present'

    source_labels = {
        'passive_check': 'passive header/content analysis',
        'passive_probe': 'passive observation of server behavior',
        'active_probe': 'active injection probe with behavioral diffing',
        'active_probe_confirmed': 'active injection probe with measurable response anomaly'
    }
    source_desc = source_labels.get(detection_source, 'automated analysis')
    confidence_note = f'{strength} confidence ({confidence:.0%}): {source_desc} — {qualifier}'

    return {
        'what': what,
        'why_it_matters': why,
        'location': where,
        'reference': {
            'cwe': kb['cwe'],
            'owasp': kb['owasp']
        },
        'remediation': {
            'guidance': kb['remediation'],
            'suggested_code_fix': None
        },
        'confidence_note': confidence_note
    }


def check_security_headers(url, session):
    findings = []
    try:
        resp = session.get(url, timeout=PASSIVE_TIMEOUT, allow_redirects=True, verify=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        parsed = urlparse(url)

        if 'content-security-policy' not in headers:
            findings.append({
                'check_name': 'missing_csp',
                'confidence': 0.85,
                'explanation': _build_explanation(
                    'missing_csp', url, 0.85, 'passive_check',
                    path=parsed.path
                )
            })

        if 'strict-transport-security' not in headers:
            findings.append({
                'check_name': 'missing_hsts',
                'confidence': 0.80,
                'explanation': _build_explanation(
                    'missing_hsts', url, 0.80, 'passive_check',
                    path=parsed.path
                )
            })

        if 'x-frame-options' not in headers and 'content-security-policy' not in headers:
            findings.append({
                'check_name': 'missing_xfo',
                'confidence': 0.75,
                'explanation': _build_explanation(
                    'missing_xfo', url, 0.75, 'passive_check',
                    path=parsed.path
                )
            })

        server = headers.get('server', '')
        if server and re.search(r'[\d\.]+', server):
            findings.append({
                'check_name': 'server_banner_disclosure',
                'confidence': 0.90,
                'explanation': _build_explanation(
                    'server_banner_disclosure', url, 0.90, 'passive_check',
                    path=parsed.path, extra_detail=server
                )
            })

        for cookie_str in resp.headers.get('Set-Cookie', '').split(','):
            cookie = cookie_str.strip().lower()
            if not cookie:
                continue
            issues = []
            if 'httponly' not in cookie:
                issues.append('HttpOnly')
            if 'secure' not in cookie:
                issues.append('Secure')
            if 'samesite' not in cookie:
                issues.append('SameSite')
            if issues:
                findings.append({
                    'check_name': 'insecure_cookies',
                    'confidence': 0.85,
                    'explanation': _build_explanation(
                        'insecure_cookies', url, 0.85, 'passive_check',
                        path=parsed.path,
                        extra_detail=', '.join(issues)
                    )
                })

    except requests.exceptions.SSLError:
        findings.append({
            'check_name': 'weak_tls',
            'confidence': 0.90,
            'explanation': _build_explanation(
                'weak_tls', url, 0.90, 'passive_check',
                extra_detail='SSL/TLS handshake failure'
            )
        })
    except Exception:
        pass

    return findings


def check_cors(url, session):
    findings = []
    try:
        resp = session.get(url, timeout=PASSIVE_TIMEOUT, allow_redirects=True)
        acao = resp.headers.get('Access-Control-Allow-Origin', '')
        acac = resp.headers.get('Access-Control-Allow-Credentials', '')

        if acao == '*' and acac.lower() == 'true':
            parsed = urlparse(url)
            findings.append({
                'check_name': 'cors_misconfiguration',
                'confidence': 0.95,
                'explanation': _build_explanation(
                    'cors_misconfiguration', url, 0.95, 'passive_check',
                    path=parsed.path
                )
            })
    except Exception:
        pass
    return findings


def check_error_disclosure(url, session):
    findings = []
    malformed_urls = [
        urljoin(url, '/%00'),
        urljoin(url, '/?q=<script>'),
        urljoin(url, "/?' OR 1=1--"),
    ]
    error_patterns = [
        r'SyntaxError', r'ReferenceError', r'TypeError',
        r'SQLite', r'PDOException', r'MySQL',
        r'Traceback \(most recent', r'at line \d+',
        r'Exception in', r'Stack Trace'
    ]
    for murl in malformed_urls:
        try:
            resp = session.get(murl, timeout=PASSIVE_TIMEOUT)
            for pattern in error_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    parsed = urlparse(murl)
                    findings.append({
                        'check_name': 'error_disclosure',
                        'confidence': 0.80,
                        'explanation': _build_explanation(
                            'error_disclosure', url, 0.80, 'passive_check',
                            path=parsed.path,
                            extra_detail=f'error pattern "{pattern}" matched'
                        )
                    })
                    return findings
        except Exception:
            continue
    return findings


def check_exposed_metadata(url, session):
    findings = []
    sensitive_paths = [
        ('/.git/config', 'repositoryformatversion'),
        ('/.env', '='),
        ('/robots.txt', 'disallow')
    ]
    for sp, indicator in sensitive_paths:
        try:
            target = urljoin(url, sp)
            resp = session.get(target, timeout=PASSIVE_TIMEOUT)
            if resp.status_code == 200 and indicator.lower() in resp.text.lower():
                parsed = urlparse(target)
                file_detail = sp
                if sp == '/.git/config':
                    file_detail = '.git directory accessible — contains repository metadata'
                elif sp == '/.env':
                    file_detail = '.env file accessible — contains environment variables/secrets'
                elif sp == '/robots.txt':
                    file_detail = 'robots.txt reveals hidden admin paths via Disallow directives'

                findings.append({
                    'check_name': 'exposed_metadata',
                    'confidence': 0.95 if sp != '/robots.txt' else 0.60,
                    'explanation': _build_explanation(
                        'exposed_metadata', url,
                        0.95 if sp != '/robots.txt' else 0.60,
                        'passive_check',
                        path=parsed.path,
                        extra_detail=file_detail
                    )
                })
        except Exception:
            continue
    return findings


def check_open_redirect(url, session):
    findings = []
    redirect_params = ['next', 'redirect', 'return', 'url', 'continue', 'dest']
    parsed = urlparse(url)
    for param in redirect_params:
        try:
            test_url = f"{url}?{param}=https://evil.example.com"
            resp = session.get(test_url, timeout=PASSIVE_TIMEOUT, allow_redirects=False)
            location = resp.headers.get('Location', '')
            if 'evil.example.com' in location:
                findings.append({
                    'check_name': 'open_redirect',
                    'confidence': 0.90,
                    'explanation': _build_explanation(
                        'open_redirect', url, 0.90, 'passive_probe',
                        path=parsed.path, param=param
                    )
                })
                break
        except Exception:
            continue
    return findings


def check_tls(url, session):
    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    if parsed.scheme != 'https':
        findings.append({
            'check_name': 'weak_tls',
            'confidence': 0.90,
            'explanation': _build_explanation(
                'weak_tls', url, 0.90, 'passive_check',
                extra_detail='Site does not use HTTPS — plain HTTP connection'
            )
        })
        return findings

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, port))
            cert = s.getpeercert()
            protocol = s.version()

            if protocol in ('TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'):
                findings.append({
                    'check_name': 'weak_tls',
                    'confidence': 0.95,
                    'explanation': _build_explanation(
                        'weak_tls', url, 0.95, 'passive_check',
                        extra_detail=f'Negotiated protocol: {protocol} (deprecated)'
                    )
                })

            if cert:
                not_after = cert.get('notAfter', '')
                if not_after:
                    from datetime import datetime
                    exp = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    if exp < datetime.utcnow():
                        findings.append({
                            'check_name': 'weak_tls',
                            'confidence': 0.95,
                            'explanation': _build_explanation(
                                'weak_tls', url, 0.95, 'passive_check',
                                extra_detail=f'Certificate expired: {not_after}'
                            )
                        })
    except Exception:
        pass
    return findings


def run_passive_checks(url, session):
    findings = []
    findings.extend(check_security_headers(url, session))
    findings.extend(check_cors(url, session))
    findings.extend(check_error_disclosure(url, session))
    findings.extend(check_exposed_metadata(url, session))
    findings.extend(check_open_redirect(url, session))
    findings.extend(check_tls(url, session))
    return findings


def run_active_sqli_check(url, session):
    findings = []
    test_payloads = ["'", "1' OR '1'='1", "1' AND '1'='1", "1' UNION SELECT NULL--"]
    baseline_resp = None
    try:
        baseline_resp = session.get(url, timeout=ACTIVE_TIMEOUT)
    except Exception:
        return findings

    parsed = urlparse(url)

    for payload in test_payloads:
        try:
            test_url = f"{url}?id={payload}"
            resp = session.get(test_url, timeout=ACTIVE_TIMEOUT)
            baseline_len = len(baseline_resp.text)
            resp_len = len(resp.text)

            if baseline_resp.status_code != resp.status_code:
                if any(kw in resp.text.lower() for kw in ['sql', 'syntax', 'mysql', 'sqlite', 'error', 'query']):
                    findings.append({
                        'check_name': 'sqli_indicator',
                        'confidence': 0.85,
                        'explanation': _build_explanation(
                            'sqli_indicator', url, 0.85, 'active_probe_confirmed',
                            path=parsed.path, param='id',
                            extra_detail=f'Status changed from {baseline_resp.status_code} to {resp.status_code} with SQL error keywords'
                        ),
                        'evidence': {
                            'request': f'GET {test_url}',
                            'baseline_status': baseline_resp.status_code,
                            'probe_status': resp.status_code,
                            'note': 'Query logic altered - no data extracted'
                        }
                    })
                    return findings

            if abs(resp_len - baseline_len) > max(500, baseline_len * 0.3):
                findings.append({
                    'check_name': 'sqli_indicator',
                    'confidence': 0.65,
                    'explanation': _build_explanation(
                        'sqli_indicator', url, 0.65, 'active_probe',
                        path=parsed.path, param='id',
                        extra_detail=f'Response size changed from {baseline_len} to {resp_len} bytes'
                    )
                })
                return findings
        except Exception:
            continue
    return findings


def run_active_xss_check(url, session):
    findings = []
    parsed = urlparse(url)
    try:
        test_url = f"{url}?q={ACTIVE_MARKER}"
        resp = session.get(test_url, timeout=ACTIVE_TIMEOUT)
        if ACTIVE_MARKER in resp.text:
            content_type = resp.headers.get('Content-Type', '')
            if 'html' in content_type or 'text' in content_type:
                findings.append({
                    'check_name': 'xss_reflection',
                    'confidence': 0.80,
                    'explanation': _build_explanation(
                        'xss_reflection', url, 0.80, 'active_probe_confirmed',
                        path=parsed.path, param='q',
                        extra_detail='Probe marker found in HTML response body'
                    ),
                    'evidence': {
                        'request': f'GET {test_url}',
                        'marker': ACTIVE_MARKER,
                        'reflected': True,
                        'note': 'Marker reflection confirmed - no exploit payload sent'
                    }
                })
    except Exception:
        pass
    return findings


def run_active_idor_check(url, session):
    findings = []
    test_ids = [1, 2, 0, -1, 99999]
    baseline_resp = None
    try:
        baseline_resp = session.get(f"{url}?id=1", timeout=ACTIVE_TIMEOUT)
    except Exception:
        return findings

    parsed = urlparse(url)
    baseline_len = len(baseline_resp.text)
    different_responses = 0

    for tid in test_ids:
        try:
            resp = session.get(f"{url}?id={tid}", timeout=ACTIVE_TIMEOUT)
            if resp.status_code == 200 and abs(len(resp.text) - baseline_len) > 100:
                different_responses += 1
        except Exception:
            continue

    if different_responses >= 2:
        findings.append({
            'check_name': 'idor_indicator',
            'confidence': 0.70,
            'explanation': _build_explanation(
                'idor_indicator', url, 0.70, 'active_probe',
                path=parsed.path, param='id',
                extra_detail=f'{different_responses}/{len(test_ids)} ID variations returned distinct responses'
            )
        })

    return findings


def run_active_auth_bypass_check(url, session):
    findings = []
    admin_paths = ['/admin', '/admin/', '/dashboard', '/api/admin', '/management']
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for ap in admin_paths:
        try:
            resp = session.get(f"{base}{ap}", timeout=ACTIVE_TIMEOUT, allow_redirects=False)
            if resp.status_code == 200:
                body = resp.text.lower()
                if any(kw in body for kw in ['dashboard', 'admin panel', 'manage', 'settings', 'users list']):
                    findings.append({
                        'check_name': 'auth_bypass',
                        'confidence': 0.75,
                        'explanation': _build_explanation(
                            'auth_bypass', url, 0.75, 'active_probe',
                            path=ap,
                            extra_detail=f'Admin content rendered at {ap} without auth redirect'
                        )
                    })
                    break
        except Exception:
            continue
    return findings


def run_active_checks(url, session):
    findings = []
    findings.extend(run_active_sqli_check(url, session))
    findings.extend(run_active_xss_check(url, session))
    findings.extend(run_active_idor_check(url, session))
    findings.extend(run_active_auth_bypass_check(url, session))
    return findings


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'})


@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target_url = data.get('target_url', '')
    mode = data.get('mode', 'passive')
    verbose_evidence = data.get('verbose_evidence', False)

    if not target_url:
        return jsonify({'error': 'target_url is required'}), 400

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'SentinelAI-DAST/1.0 (Security Scanner)',
        'Accept': 'text/html,application/xhtml+xml,*/*'
    })

    findings = run_passive_checks(target_url, session)

    if mode == 'active':
        findings.extend(run_active_checks(target_url, session))

    if not verbose_evidence:
        for f in findings:
            f.pop('evidence', None)

    return jsonify({
        'target_url': target_url,
        'mode': mode,
        'finding_count': len(findings),
        'findings': findings
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=True)
