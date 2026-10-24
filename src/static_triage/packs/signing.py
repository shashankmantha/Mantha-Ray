from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

# minisign signatures (https://jedisct1.github.io/minisign/), verify only:
#   public key  line 2 = base64("Ed" + key_id[8] + public_key[32])
#   signature   line 2 = base64("ED" + key_id[8] + signature[64]), over BLAKE2b-512(file)
#               line 3 = "trusted comment: <text>"
#               line 4 = base64(signature[64] over signature + text)
# Only prehashed ("ED") signatures are accepted; Hermit and `minisign -S`
# both make them.

TRUSTED_COMMENT_RE = re.compile(r"^mantha-packs (\S+) sha256:([0-9a-f]{64})$")
MAX_SIGNATURE_BYTES = 4096
MAX_SIGNED_BYTES = 256 * 2**20


class SignatureError(Exception):
    pass


def _b64(lines: list[str], index: int, what: str) -> bytes:
    try:
        return base64.b64decode(lines[index].strip(), validate=True)
    except (IndexError, ValueError) as exc:
        raise SignatureError(f"{what}: not a minisign file (line {index + 1})") from exc


def load_public_key(text: str) -> tuple[bytes, object]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    lines = [line for line in text.strip().splitlines() if line.strip()]
    raw = _b64(lines, 1 if len(lines) > 1 else 0, "public key")
    if len(raw) != 42 or raw[:2] != b"Ed":
        raise SignatureError("public key: unsupported format")
    return raw[2:10], Ed25519PublicKey.from_public_bytes(raw[10:])


def verify_file(path: Path, signature_path: Path, public_key_text: str) -> str:
    """Check a minisign signature and return its trusted comment."""

    from cryptography.exceptions import InvalidSignature

    key_id, public_key = load_public_key(public_key_text)
    if signature_path.stat().st_size > MAX_SIGNATURE_BYTES:
        raise SignatureError("signature file is too large")
    try:
        lines = signature_path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise SignatureError("signature file is not text") from exc
    signature = _b64(lines, 1, "signature")
    if len(signature) != 74:
        raise SignatureError("signature: unsupported format")
    if signature[:2] != b"ED":
        raise SignatureError("signature: only prehashed (ED) minisign signatures are accepted")
    if signature[2:10] != key_id:
        raise SignatureError("signature was made with a different key")
    if len(lines) < 4 or not lines[2].startswith("trusted comment: "):
        raise SignatureError("signature: missing trusted comment")
    comment = lines[2][len("trusted comment: "):]

    if path.stat().st_size > MAX_SIGNED_BYTES:
        raise SignatureError("bundle is larger than allowed")
    digest = hashlib.blake2b(digest_size=64)
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    try:
        public_key.verify(signature[10:], digest.digest())
        public_key.verify(_b64(lines, 3, "signature"), signature[10:] + comment.encode())
    except InvalidSignature as exc:
        raise SignatureError("signature does not match the file (tampered or wrong key)") from exc
    return comment


def parse_trusted_comment(comment: str) -> tuple[str, str]:
    """`mantha-packs <version> sha256:<hash>`, matched as a whole, never by prefix."""

    match = TRUSTED_COMMENT_RE.fullmatch(comment)
    if match is None:
        raise SignatureError(
            f"signed comment {comment[:120]!r} isn't 'mantha-packs <version> sha256:<hash>'"
        )
    return match.group(1), match.group(2)
