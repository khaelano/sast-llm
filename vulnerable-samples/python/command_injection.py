"""
VULNERABLE SAMPLE: Command Injection
Kategori: OWASP A03:2021 - Injection
"""

import os
import subprocess


# ===== VULNERABLE: OS Command Injection via os.system =====
def ping_host_vulnerable(hostname):
    """Ping sebuah host - RENTAN terhadap Command Injection"""
    # VULNERABILITY: Input langsung dimasukkan ke shell command
    os.system("ping -c 4 " + hostname)


# ===== VULNERABLE: Command Injection via subprocess dengan shell=True =====
def get_file_info_vulnerable(filename):
    """Mendapatkan info file - RENTAN"""
    # VULNERABILITY: shell=True + input langsung = command injection
    result = subprocess.run(
        "file " + filename, shell=True, capture_output=True, text=True
    )
    return result.stdout


# ===== VULNERABLE: Command Injection via os.popen =====
def compress_file_vulnerable(filepath):
    """Kompres file - RENTAN"""
    # VULNERABILITY: os.popen dengan input tidak tervalidasi
    output = os.popen(f"gzip {filepath}").read()
    return output


# ===== VULNERABLE: Command Injection via eval =====
def calculate_vulnerable(expression):
    """Kalkulasi ekspresi - RENTAN terhadap Code Injection"""
    # VULNERABILITY: eval() mengeksekusi kode Python arbitrer
    result = eval(expression)
    return result


# ===== SECURE: Subprocess dengan argument list =====
def ping_host_secure(hostname):
    """Ping sebuah host - AMAN"""
    # Validasi input terlebih dahulu
    import re

    if not re.match(r"^[a-zA-Z0-9.\-]+$", hostname):
        raise ValueError("Invalid hostname")

    # SECURE: Argument list, bukan string, tanpa shell=True
    result = subprocess.run(
        ["ping", "-c", "4", hostname], capture_output=True, text=True, timeout=10
    )
    return result.stdout


# ===== SECURE: Subprocess dengan shlex =====
def get_file_info_secure(filename):
    """Mendapatkan info file - AMAN"""
    import shlex

    # SECURE: Argument list tanpa shell=True
    result = subprocess.run(["file", filename], capture_output=True, text=True)
    return result.stdout


if __name__ == "__main__":
    # Contoh serangan Command Injection:
    # hostname = "google.com; cat /etc/passwd"
    # filename = "test.txt; rm -rf /"
    # expression = "__import__('os').system('rm -rf /')"
    print("Demo Command Injection vulnerabilities")
