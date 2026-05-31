"""
VULNERABLE SAMPLE: Path Traversal & Hardcoded Secrets
Kategori: OWASP A01:2021 - Broken Access Control
         OWASP A02:2021 - Cryptographic Failures
"""

import os
import hashlib
import jwt
import pickle
import yaml


# ============================================================
# PATH TRAVERSAL
# ============================================================


# ===== VULNERABLE: Path Traversal =====
def read_file_vulnerable(filename):
    """Membaca file dari direktori uploads - RENTAN terhadap Path Traversal"""
    # VULNERABILITY: Tidak ada validasi path, bisa diakses ../../etc/passwd
    base_dir = "/var/www/uploads/"
    filepath = base_dir + filename
    with open(filepath, "r") as f:
        return f.read()


# ===== VULNERABLE: Path Traversal dengan os.path.join =====
def download_file_vulnerable(user_input):
    """Download file - RENTAN"""
    # VULNERABILITY: os.path.join tidak mencegah path traversal jika input dimulai dengan /
    safe_dir = "/var/www/public/"
    filepath = os.path.join(safe_dir, user_input)
    with open(filepath, "rb") as f:
        return f.read()


# ===== SECURE: Path Traversal prevention =====
def read_file_secure(filename):
    """Membaca file - AMAN dengan normalisasi path"""
    base_dir = "/var/www/uploads/"
    # Normalisasi dan validasi path
    filepath = os.path.normpath(os.path.join(base_dir, filename))
    if not filepath.startswith(base_dir):
        raise ValueError("Access denied: path traversal detected")
    with open(filepath, "r") as f:
        return f.read()


# ============================================================
# HARDCODED SECRETS
# ============================================================

# ===== VULNERABLE: Hardcoded Credentials =====
DATABASE_HOST = "db.internal.company.com"
DATABASE_USER = "admin"
DATABASE_PASSWORD = "SuperSecret123!"  # VULNERABILITY: Hardcoded password
API_KEY = "sk-proj-abc123xyz789secretkey"  # VULNERABILITY: Hardcoded API key
JWT_SECRET = "my-super-secret-jwt-key-2024"  # VULNERABILITY: Hardcoded JWT secret
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # VULNERABILITY: Hardcoded AWS key
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # VULNERABILITY


def create_token_vulnerable(user_id):
    """Membuat JWT token - RENTAN karena hardcoded secret"""
    payload = {"user_id": user_id}
    # VULNERABILITY: Menggunakan hardcoded secret
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token


# ===== VULNERABLE: Weak Hashing =====
def hash_password_vulnerable(password):
    """Hash password - RENTAN karena menggunakan MD5"""
    # VULNERABILITY: MD5 sudah tidak aman untuk hashing password
    return hashlib.md5(password.encode()).hexdigest()


def hash_sha1_vulnerable(data):
    """Hash data - RENTAN karena SHA1 sudah deprecated"""
    # VULNERABILITY: SHA1 rentan terhadap collision attack
    return hashlib.sha1(data.encode()).hexdigest()


# ============================================================
# INSECURE DESERIALIZATION
# ============================================================


# ===== VULNERABLE: Pickle Deserialization =====
def load_user_session_vulnerable(session_data):
    """Load user session - RENTAN terhadap deserialization attack"""
    # VULNERABILITY: pickle.loads dapat mengeksekusi kode arbitrer
    return pickle.loads(session_data)


# ===== VULNERABLE: YAML unsafe load =====
def parse_config_vulnerable(yaml_content):
    """Parse konfigurasi YAML - RENTAN"""
    # VULNERABILITY: yaml.load() tanpa Loader bisa mengeksekusi kode
    return yaml.load(yaml_content)


# ===== SECURE: Safe YAML loading =====
def parse_config_secure(yaml_content):
    """Parse konfigurasi YAML - AMAN"""
    # SECURE: yaml.safe_load() tidak mengeksekusi kode
    return yaml.safe_load(yaml_content)


# ===== SECURE: Proper password hashing =====
def hash_password_secure(password):
    """Hash password - AMAN menggunakan bcrypt"""
    import bcrypt

    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)


if __name__ == "__main__":
    print("Demo Path Traversal, Hardcoded Secrets, and Insecure Deserialization")
    # Path traversal attack: filename = "../../etc/passwd"
    # download_file: user_input = "/etc/shadow"
