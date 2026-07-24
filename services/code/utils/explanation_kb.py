import json
import os

class ExplanationKB:
    def __init__(self):
        self.kb_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'cwe_kb.json')
        self.kb = self._load_kb()
    
    def _load_kb(self):
        if os.path.exists(self.kb_path):
            with open(self.kb_path, 'r') as f:
                return json.load(f)
        return self._get_default_kb()
    
    def _get_default_kb(self):
        return {
            'sql_injection': {
                'cwe': 'CWE-89',
                'name': 'SQL Injection',
                'description': 'Improper neutralization of special elements used in an SQL command.',
                'severity': 'high',
                'owasp': 'A03:2021 - Injection',
                'remediation': [
                    'Use parameterized queries or prepared statements',
                    'Use stored procedures',
                    'Validate and sanitize user input',
                    'Apply principle of least privilege'
                ],
                'examples': [
                    'string query = "SELECT * FROM users WHERE id = " + userId;',
                    'db.execute("DELETE FROM orders WHERE id=" + orderId);'
                ],
                'fix_patterns': [
                    'Use ? placeholders for parameters',
                    'Use parameterized query methods',
                    'Validate input against whitelist'
                ]
            },
            'xss': {
                'cwe': 'CWE-79',
                'name': 'Cross-site Scripting (XSS)',
                'description': 'Improper neutralization of input during web page generation.',
                'severity': 'medium',
                'owasp': 'A03:2021 - Injection',
                'remediation': [
                    'Encode output data',
                    'Validate and sanitize input',
                    'Use Content Security Policy (CSP)',
                    'Use HTTPOnly cookies'
                ],
                'examples': [
                    'document.innerHTML = userInput;',
                    'response.send(`<div>${userInput}</div>`);'
                ],
                'fix_patterns': [
                    'Escape HTML entities',
                    'Use textContent instead of innerHTML',
                    'Sanitize with DOMPurify or similar'
                ]
            },
            'hardcoded_credentials': {
                'cwe': 'CWE-798',
                'name': 'Use of Hard-coded Credentials',
                'description': 'Product contains hard-coded credentials such as a password or cryptographic key.',
                'severity': 'critical',
                'owasp': 'A07:2021 - Identification and Authentication Failures',
                'remediation': [
                    'Store credentials in environment variables',
                    'Use a secrets manager',
                    'Use credential vaults',
                    'Implement proper key rotation'
                ],
                'examples': [
                    'const password = "admin123";',
                    'DB_PASSWORD = "secret_pass"'
                ],
                'fix_patterns': [
                    'Move to environment variables',
                    'Use process.env or config files',
                    'Use secret management services'
                ]
            },
            'command_injection': {
                'cwe': 'CWE-78',
                'name': 'OS Command Injection',
                'description': 'Improper neutralization of special elements used in an OS command.',
                'severity': 'critical',
                'owasp': 'A03:2021 - Injection',
                'remediation': [
                    'Avoid calling OS commands directly',
                    'Use language-level APIs instead',
                    'Validate and sanitize input',
                    'Use parameterized APIs'
                ],
                'examples': [
                    'exec("cat " + filename);',
                    'system("ping " + userInput);'
                ],
                'fix_patterns': [
                    'Use subprocess with argument list',
                    'Validate input against whitelist',
                    'Use built-in language functions'
                ]
            },
            'path_traversal': {
                'cwe': 'CWE-22',
                'name': 'Path Traversal',
                'description': 'Improper limitation of a pathname to a restricted directory.',
                'severity': 'high',
                'owasp': 'A01:2021 - Broken Access Control',
                'remediation': [
                    'Validate and normalize file paths',
                    'Use chroot or jail environments',
                    'Implement proper access controls',
                    'Use allowlisting for file access'
                ],
                'examples': [
                    'readFile("/data/" + userPath);',
                    'fs.readFileSync(baseDir + "/" + filename);'
                ],
                'fix_patterns': [
                    'Resolve and validate path is within allowed directory',
                    'Use path.normalize and check prefix',
                    'Implement allowlist for accessible paths'
                ]
            },
            'not_vulnerable': {
                'cwe': 'N/A',
                'name': 'Not Vulnerable',
                'description': 'No vulnerability detected in the code.',
                'severity': 'info',
                'owasp': 'N/A',
                'remediation': [],
                'examples': [],
                'fix_patterns': []
            }
        }
    
    def get_explanation(self, vulnerability_type, code_snippet):
        if vulnerability_type not in self.kb:
            vulnerability_type = 'not_vulnerable'
        
        entry = self.kb[vulnerability_type]
        
        explanation = {
            'cwe': entry['cwe'],
            'name': entry['name'],
            'description': entry['description'],
            'severity': entry['severity'],
            'owasp': entry['owasp'],
            'remediation': entry['remediation'],
            'code_context': self._extract_code_context(code_snippet, vulnerability_type),
            'fix_suggestions': entry['fix_patterns']
        }
        
        return explanation
    
    def _extract_code_context(self, code, vulnerability_type):
        lines = code.split('\n')
        vulnerable_lines = []
        
        patterns = {
            'sql_injection': ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'query', 'execute'],
            'xss': ['innerHTML', 'outerHTML', 'document.write', 'insertAdjacentHTML'],
            'hardcoded_credentials': ['password', 'secret', 'key', 'token', 'api_key'],
            'command_injection': ['exec', 'system', 'popen', 'eval', 'spawn'],
            'path_traversal': ['readFile', 'writeFile', 'open', 'path', 'fs.']
        }
        
        if vulnerability_type in patterns:
            for i, line in enumerate(lines):
                for pattern in patterns[vulnerability_type]:
                    if pattern.lower() in line.lower():
                        vulnerable_lines.append({
                            'line_number': i + 1,
                            'code': line.strip(),
                            'pattern_matched': pattern
                        })
        
        return vulnerable_lines
    
    def save_kb(self):
        os.makedirs(os.path.dirname(self.kb_path), exist_ok=True)
        with open(self.kb_path, 'w') as f:
            json.dump(self.kb, f, indent=2)
    
    def add_entry(self, vulnerability_type, entry):
        self.kb[vulnerability_type] = entry
        self.save_kb()
