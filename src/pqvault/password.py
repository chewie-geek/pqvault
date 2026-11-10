"""Password-based key derivation with Argon2id (memory-hard)."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from . import PQVaultError

KEY_SIZE = 32
SALT_SIZE = 16


@dataclass(frozen=True)
class Argon2Params:
    memory_kib: int
    iterations: int
    lanes: int

    def validate(self) -> None:
        # Bounds stop a malicious file from making decryption hang or exhaust RAM.
        if not (8 * self.lanes <= self.memory_kib <= 4 * 1024 * 1024):
            raise PQVaultError("Argon2 memory parameter out of allowed range")
        if not (1 <= self.iterations <= 32):
            raise PQVaultError("Argon2 iteration parameter out of allowed range")
        if not (1 <= self.lanes <= 64):
            raise PQVaultError("Argon2 lanes parameter out of allowed range")


# 256 MiB, 3 passes, 4 lanes: roughly 0.5-1 s on a modern laptop.
DEFAULT_PARAMS = Argon2Params(memory_kib=256 * 1024, iterations=3, lanes=4)


def derive_key(password: bytes, salt: bytes, params: Argon2Params) -> bytes:
    if not password:
        raise PQVaultError("password must not be empty")
    params.validate()
    kdf = Argon2id(
        salt=salt,
        length=KEY_SIZE,
        iterations=params.iterations,
        lanes=params.lanes,
        memory_cost=params.memory_kib,
    )
    return kdf.derive(password)
