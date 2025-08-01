import re

# Patterns for each attack type
XSS_PATTERNS = [
    r'<script[\s\S]*?>[\s\S]*?<\/script>',  # full script tag
    r'<script[\s\S]*?>',                     # opening script tag
    r'onerror\s*=\s*(["\']).+?\1',       # onerror with value
    r'onload\s*=\s*(["\']).+?\1',        # onload with value
    r'javascript:[^\s]+',                    # javascript: URI
    r'<img[^>]+src\s*=\s*(["\']).+?\1',  # img src with value
    r'<svg[\s\S]*?>',                       # svg tag
    r'<iframe[\s\S]*?>',                    # iframe tag
    r'document\.cookie',                     # document.cookie access
    r'alert\s*\([\s\S]*?\)',             # alert( ... )
    r'\bon\w+\s*=\s*(["\']).+?\1',    # on* attributes with value
]
CSRF_PATTERNS = [
    r'<form[^>]*method=["\']?post["\']?',
    r'csrf',
    r'cross.?site.?request.?forgery',
    r'\btoken=\b',
]
SSRF_PATTERNS = [
    r'file://',
    r'gopher://',
    r'ftp://',
    r'http://127\.0\.0\.1',
    r'https?://127\.0\.0\.1',
    r'127\.0\.0\.1',
    r'localhost',
    r'internal',
    r'169\.254\.',
    r'10\.\d+\.\d+\.\d+',
    r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+',
    r'192\.168\.\d+\.\d+',
    r'localhost:\d+',
    r'\bssrf\b',
    r'metadata',
    r'aws',
    r'azure',
]
SQLI_PATTERNS = [
    r'(\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bunion\b|\bwhere\b|\blike\b)',
    r'\bor\b.+?=.+', r'\band\b.+?=.+', r'--', r';', r'\bcast\b', r'\bsleep\b', r'\bbenchmark\b',
    r'\b1=1\b', r'\b1=0\b', r'\btrue\b', r'\bfalse\b', r'\bsqli\b',
]

def detect_attack_from_strings(url, payload):
    url = str(url).strip().lower()
    payload = str(payload).strip().lower()
    # XSS
    for pattern in XSS_PATTERNS:
        if (payload and re.search(pattern, payload, re.IGNORECASE)) or (url and re.search(pattern, url, re.IGNORECASE)):
            return 'malicious', 'xss'
    # CSRF
    for pattern in CSRF_PATTERNS:
        if (payload and re.search(pattern, payload, re.IGNORECASE)) or (url and re.search(pattern, url, re.IGNORECASE)):
            return 'malicious', 'csrf'
    # SSRF
    for pattern in SSRF_PATTERNS:
        if (payload and re.search(pattern, payload, re.IGNORECASE)) or (url and re.search(pattern, url, re.IGNORECASE)):
            return 'malicious', 'ssrf'
    # SQLi
    for pattern in SQLI_PATTERNS:
        if (payload and re.search(pattern, payload, re.IGNORECASE)) or (url and re.search(pattern, url, re.IGNORECASE)):
            return 'malicious', 'sqli'
    return 'benign', 'benign'
