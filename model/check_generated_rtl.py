"""Cross-check generated RTL constants and all testbench AES vectors."""

from pathlib import Path
import importlib.util
import re


ROOT = Path(__file__).resolve().parents[1]
RTL_PATH = ROOT / "rtl" / "aes256_axis_encryptor.v"
MODEL_PATH = Path(__file__).with_name("aes256_reference.py")

model_spec = importlib.util.spec_from_file_location("aes256_reference", MODEL_PATH)
model = importlib.util.module_from_spec(model_spec)
assert model_spec.loader is not None
model_spec.loader.exec_module(model)

rtl_text = RTL_PATH.read_text(encoding="ascii")
entries = re.findall(
    r"8'h([0-9a-f]{2}): aes_sbox = 8'h([0-9a-f]{2});",
    rtl_text,
    flags=re.IGNORECASE,
)
rtl_sbox = [None] * 256
for address_hex, value_hex in entries:
    rtl_sbox[int(address_hex, 16)] = int(value_hex, 16)

if len(entries) != 256 or any(value is None for value in rtl_sbox):
    raise AssertionError("RTL must contain exactly one S-box entry for every byte value")
if tuple(rtl_sbox) != model.SBOX:
    raise AssertionError("RTL S-box differs from the independent semantic model")

key_nist = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d7781"
    "1f352c073b6108d72d9810a30914dff4"
)
vectors = (
    (key_nist, "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8"),
    (key_nist, "ae2d8a571e03ac9c9eb76fac45af8e51", "591ccb10d410ed26dc5ba74a31362870"),
    (key_nist, "30c81c46a35ce411e5fbc1191a0a52ef", "b6ed21b99ca6f4f9f153e7b1beafed1d"),
    (key_nist, "f69f2445df4f9b17ad2b417be66c3710", "23304b7a39f9f3ff067d8d8f9e24ecc7"),
    (
        bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        "00112233445566778899aabbccddeeff",
        "8ea2b7ca516745bfeafc49904b496089",
    ),
)

for key, plaintext_hex, expected_hex in vectors:
    result = model.encrypt_block(key, bytes.fromhex(plaintext_hex)).hex()
    if result != expected_hex:
        raise AssertionError(f"Vector mismatch: expected {expected_hex}, received {result}")

print("PASS: RTL S-box and 5 AES-256 testbench vectors match the semantic model")
