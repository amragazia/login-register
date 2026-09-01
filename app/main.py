import hashlib
import hmac
import secrets


def hash_func(password: str) -> str:
    """Hash a password with a random salt using the standard-library scrypt KDF."""
    salt = secrets.token_bytes(16)
    hashed = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${hashed.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Compare a password against a scrypt hash without timing leaks."""
    try:
        # Accounts created by the original demo used SHA-256 without a salt.
        # Permit one successful login so routes can upgrade those records below.
        if "$" not in stored_hash:
            return hmac.compare_digest(
                hashlib.sha256(password.encode()).hexdigest(), stored_hash
            )
        scheme, salt_hex, hash_hex = stored_hash.split("$", 2)
        if scheme != "scrypt":
            return False
        actual = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1
        )
        return hmac.compare_digest(actual.hex(), hash_hex)
    except (TypeError, ValueError):
        return False


def is_legacy_password_hash(stored_hash: str) -> bool:
    return "$" not in stored_hash
