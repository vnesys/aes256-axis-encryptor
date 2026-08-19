"""Independent AES-256 encryption reference model for RTL verification."""

from __future__ import annotations


SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)


def _xtime(value: int) -> int:
    """Multiply one byte by x in GF(2^8)."""
    return ((value << 1) ^ (0x1B if value & 0x80 else 0)) & 0xFF


def _sub_word(word: list[int]) -> list[int]:
    """Apply the AES S-box to one four-byte key word."""
    return [SBOX[value] for value in word]


def expand_key(key: bytes) -> list[bytes]:
    """Expand a 256-bit key into the fifteen AES-256 round keys."""
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")

    words = [list(key[index:index + 4]) for index in range(0, 32, 4)]
    rcon = 0x01

    for index in range(8, 60):
        temporary = words[index - 1].copy()
        if index % 8 == 0:
            temporary = _sub_word(temporary[1:] + temporary[:1])
            temporary[0] ^= rcon
            rcon = _xtime(rcon)
        elif index % 8 == 4:
            temporary = _sub_word(temporary)
        words.append([left ^ right for left, right in zip(words[index - 8], temporary)])

    return [bytes(sum(words[index:index + 4], [])) for index in range(0, 60, 4)]


def _add_round_key(state: list[int], round_key: bytes) -> list[int]:
    """XOR one state with one round key."""
    return [value ^ key_byte for value, key_byte in zip(state, round_key)]


def _sub_bytes(state: list[int]) -> list[int]:
    """Apply the AES S-box to every state byte."""
    return [SBOX[value] for value in state]


def _shift_rows(state: list[int]) -> list[int]:
    """Rotate the four AES state rows in FIPS column-major order."""
    order = (0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11)
    return [state[index] for index in order]


def _mix_columns(state: list[int]) -> list[int]:
    """Apply the AES MixColumns transform to all four columns."""
    mixed: list[int] = []
    for offset in range(0, 16, 4):
        byte_zero, byte_one, byte_two, byte_three = state[offset:offset + 4]
        twice_zero = _xtime(byte_zero)
        twice_one = _xtime(byte_one)
        twice_two = _xtime(byte_two)
        twice_three = _xtime(byte_three)
        mixed.extend(
            (
                twice_zero ^ twice_one ^ byte_one ^ byte_two ^ byte_three,
                byte_zero ^ twice_one ^ twice_two ^ byte_two ^ byte_three,
                byte_zero ^ byte_one ^ twice_two ^ twice_three ^ byte_three,
                twice_zero ^ byte_zero ^ byte_one ^ byte_two ^ twice_three,
            )
        )
    return mixed


def encrypt_block(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt one 128-bit plaintext block with AES-256."""
    if len(plaintext) != 16:
        raise ValueError("AES uses a 16-byte plaintext block")

    round_keys = expand_key(key)
    state = _add_round_key(list(plaintext), round_keys[0])

    for round_index in range(1, 14):
        state = _add_round_key(_mix_columns(_shift_rows(_sub_bytes(state))), round_keys[round_index])

    state = _add_round_key(_shift_rows(_sub_bytes(state)), round_keys[14])
    return bytes(state)


def _run_known_answer_tests() -> None:
    """Check the semantic model against published AES-256 vectors."""
    vectors = (
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089",
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "6bc1bee22e409f96e93d7e117393172a",
            "f3eed1bdb5d2a03c064b5a7e3db181f8",
        ),
    )

    for key_hex, plaintext_hex, expected_hex in vectors:
        actual = encrypt_block(bytes.fromhex(key_hex), bytes.fromhex(plaintext_hex)).hex()
        if actual != expected_hex:
            raise AssertionError(f"AES-256 mismatch: expected {expected_hex}, received {actual}")

    print(f"PASS: {len(vectors)} AES-256 known-answer tests")


if __name__ == "__main__":
    _run_known_answer_tests()
