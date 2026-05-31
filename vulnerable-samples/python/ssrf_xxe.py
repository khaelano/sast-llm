"""
VULNERABLE SAMPLE: SSRF & XXE & Open Redirect
Kategori: OWASP A10:2021 - SSRF
         OWASP A05:2021 - Security Misconfiguration (XXE)
"""

import requests
import urllib.request
from lxml import etree
from flask import Flask, redirect, request as flask_request


app = Flask(__name__)


# ============================================================
# SERVER-SIDE REQUEST FORGERY (SSRF)
# ============================================================


# ===== VULNERABLE: SSRF =====
def fetch_url_vulnerable(url):
    """Mengambil konten dari URL - RENTAN terhadap SSRF"""
    # VULNERABILITY: Tidak ada validasi URL, bisa mengakses internal resources
    # Attacker bisa akses: http://169.254.169.254/latest/meta-data/ (AWS metadata)
    # Atau: http://localhost:6379 (Redis), http://internal-service/admin
    response = requests.get(url, timeout=10)
    return response.text


def fetch_image_vulnerable(image_url):
    """Download gambar dari URL - RENTAN terhadap SSRF"""
    # VULNERABILITY: urllib tidak memvalidasi skema URL
    with urllib.request.urlopen(image_url) as response:
        return response.read()


@app.route("/proxy")
def proxy_vulnerable():
    """Proxy endpoint - RENTAN"""
    # VULNERABILITY: Parameter URL langsung digunakan tanpa validasi
    target_url = flask_request.args.get("url")
    response = requests.get(target_url)
    return response.text


# ===== SECURE: SSRF prevention =====
def fetch_url_secure(url):
    """Mengambil konten dari URL - AMAN"""
    from urllib.parse import urlparse
    import ipaddress

    parsed = urlparse(url)

    # Whitelist skema yang diizinkan
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP/HTTPS URLs are allowed")

    # Blokir akses ke IP internal
    hostname = parsed.hostname
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError("Access to internal IPs is not allowed")
    except ValueError:
        pass  # Bukan IP, lanjutkan

    # Whitelist domain yang diizinkan
    allowed_domains = ["api.trusted-service.com", "cdn.example.com"]
    if hostname not in allowed_domains:
        raise ValueError(f"Domain {hostname} is not in the allowlist")

    response = requests.get(url, timeout=10)
    return response.text


# ============================================================
# XML EXTERNAL ENTITY (XXE)
# ============================================================


# ===== VULNERABLE: XXE =====
def parse_xml_vulnerable(xml_content):
    """Parse XML - RENTAN terhadap XXE"""
    # VULNERABILITY: Parser default lxml mengizinkan external entities
    # Attack payload:
    # <?xml version="1.0"?>
    # <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    # <data>&xxe;</data>
    parser = etree.XMLParser()
    root = etree.fromstring(xml_content.encode(), parser)
    return etree.tostring(root)


# ===== SECURE: XXE prevention =====
def parse_xml_secure(xml_content):
    """Parse XML - AMAN dengan menonaktifkan external entities"""
    # SECURE: resolve_entities=False mencegah XXE
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    root = etree.fromstring(xml_content.encode(), parser)
    return etree.tostring(root)


# ============================================================
# OPEN REDIRECT
# ============================================================


# ===== VULNERABLE: Open Redirect =====
@app.route("/redirect")
def redirect_vulnerable():
    """Redirect endpoint - RENTAN terhadap Open Redirect"""
    # VULNERABILITY: URL redirect tidak divalidasi
    # Attacker bisa redirect ke: /redirect?next=https://evil.com
    next_url = flask_request.args.get("next", "/")
    return redirect(next_url)


# ===== SECURE: Open Redirect prevention =====
@app.route("/safe-redirect")
def redirect_secure():
    """Redirect endpoint - AMAN"""
    from urllib.parse import urlparse

    next_url = flask_request.args.get("next", "/")
    parsed = urlparse(next_url)

    # Hanya izinkan redirect internal (tanpa domain)
    if parsed.netloc:
        return redirect("/")

    return redirect(next_url)


if __name__ == "__main__":
    print("Demo SSRF, XXE, and Open Redirect vulnerabilities")
    # SSRF attack: url = "http://169.254.169.254/latest/meta-data/iam/credentials/"
    # XXE attack: xml dengan external entity reference
    # Open redirect: /redirect?next=https://phishing-site.com
