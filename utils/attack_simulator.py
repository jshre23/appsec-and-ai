"""
Simulates common attacks (SQLi, XSS, etc.) for demo/testing.
"""
class AttackSimulator:
    @staticmethod
    def simulate_sqli():
        return "' OR '1'='1'; -- "

    @staticmethod
    def simulate_xss():
        return "<script>alert('XSS')</script>"

    @staticmethod
    def simulate_lfi():
        return "../../../../etc/passwd"

    @staticmethod
    def simulate_rce():
        return "; ls -la;"
