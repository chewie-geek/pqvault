"""pqvault: file encryption designed to stay secure against quantum computers."""

__version__ = "0.1.0"


class PQVaultError(Exception):
    """Base error. Messages are safe to show to users."""


class DecryptionError(PQVaultError):
    """The file could not be authenticated or decrypted."""
