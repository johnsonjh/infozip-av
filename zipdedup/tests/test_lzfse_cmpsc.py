#!/usr/bin/env python3
"""cu40 regression: methods 16/99, RefPtr, and method-99/AES separation.

Requires freshly built zip30/zip, unzip60/unzip and zipdedup/zipdedup.
No external libraries or proprietary fixtures.  Production code remains C89.
"""
import pathlib
import struct
import subprocess
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
ZIP = ROOT / 'zip30' / 'zip'
UNZIP = ROOT / 'unzip60' / 'unzip'
DEDUP = ROOT / 'zipdedup' / 'zipdedup'


def run(*args, ok=(0,), input=None):
    p = subprocess.run([str(a) for a in args], input=input, capture_output=True)
    assert p.returncode in ok, (p.args, p.returncode, p.stdout[-1000:], p.stderr[-1000:])
    return p


def content(archive, name, password=None):
    args = [UNZIP, '-p']
    if password:
        args += ['-P', password]
    return run(*args, archive, name).stdout


def raw_head(archive, entry):
    data = archive.read_bytes()
    o = entry.header_offset
    assert data[o:o + 4] == b'PK\x03\x04'
    namelen, extralen = struct.unpack_from('<HH', data, o + 26)
    return data[o + 30 + namelen + extralen:o + 34 + namelen + extralen]


def test_codec(base, method, method_id, payload):
    src, dup = base / (method + '_a.bin'), base / (method + '_b.bin')
    src.write_bytes(payload)
    dup.write_bytes(payload)
    initial = base / (method + '.zip')
    deduped = base / (method + '_dedup.zip')
    created = run(ZIP, '-Z', method, initial, src.name, dup.name)
    assert (method.upper().encode() + b' compressed') in created.stdout, created.stdout
    with zipfile.ZipFile(initial) as z:
        entries = z.infolist()
        assert [e.compress_type for e in entries] == [method_id, method_id]
        assert all((e.flag_bits & 1) == 0 for e in entries)
        if method_id == 99:
            assert raw_head(initial, entries[0]) in (b'bvx-', b'bvx1', b'bvx2', b'bvxn', b'bvx$')
    assert content(initial, src.name) == payload
    run(DEDUP, initial, deduped)
    run(UNZIP, '-tq', deduped)
    with zipfile.ZipFile(deduped) as z:
        a, b = z.infolist()
        assert (a.compress_type, b.compress_type) == (method_id, 92)
        assert b.compress_size == 20
        assert b.file_size == len(payload)
        assert b.CRC == a.CRC
    assert content(deduped, src.name) == payload
    assert content(deduped, dup.name) == payload
    # Processing an already-deduplicated archive is idempotent.
    again = base / (method + '_again.zip')
    run(DEDUP, deduped, again)
    assert again.read_bytes() == deduped.read_bytes()


def test_method99_encryption(base, payload):
    src = base / 'aes_source.bin'
    src.write_bytes(payload)
    for mode in ('standard', 'quantum'):
        encrypted = base / ('aes_' + mode + '.zip')
        args = [ZIP, '-q', '-Z', 'deflate', '-eP', 'testpass', '--aes-mode', mode,
                encrypted, src.name]
        run(*args)
        assert content(encrypted, src.name, 'testpass') == payload
        listing = run(UNZIP, '-Z', '-v', encrypted).stdout
        assert b'WinZip AES encryption:' in listing
        refused = run(DEDUP, encrypted, base / ('refused_' + mode + '.zip'), ok=(1,))
        assert b'reject' in (refused.stdout + refused.stderr).lower()
        no = base / ('bad_' + mode + '.zip')
        refused = run(ZIP, '-Z', 'lzfse', '-eP', 'testpass', '--aes-mode', mode,
                      no, src.name, ok=(16,))
        assert b'cannot be combined' in (refused.stdout + refused.stderr)
        assert not no.exists()
    # One tiny AES entry triggers existing AE-2 selection; don't change it.
    small = base / 'ae2.txt'
    small.write_bytes(b'1234567')
    ae2 = base / 'aes_ae2.zip'
    run(ZIP, '-q', '-Z', 'deflate', '-eP', 'testpass', ae2, small.name)
    assert content(ae2, small.name, 'testpass') == b'1234567'
    assert b'AE-2' in run(UNZIP, '-Z', '-v', ae2).stdout
    # ZipCrypto is allowed, but zipdedup must still reject encrypted input.
    crypto = base / 'crypto_lzfse.zip'
    run(ZIP, '-q', '-Z', 'lzfse', '-P', 'testpass', crypto, src.name)
    with zipfile.ZipFile(crypto) as z:
        assert z.infolist()[0].compress_type == 99
        assert z.infolist()[0].flag_bits & 1
    assert content(crypto, src.name, 'testpass') == payload
    assert b'encrypted, type unverified' in run(UNZIP, '-Z', '-v', crypto).stdout
    run(DEDUP, crypto, base / 'refused_crypto.zip', ok=(1,))


def test_invalid_aes_label(base):
    # Central-directory-only corruptions test listing without decrypting.
    archive = (base / 'aes_standard.zip')
    data = bytearray(archive.read_bytes())
    with zipfile.ZipFile(archive) as z:
        pos = z.start_dir
    assert data[pos:pos + 4] == b'PK\x01\x02'
    assert struct.unpack_from('<H', data, pos + 10)[0] == 99
    variants = []
    v = bytearray(data)
    flags = struct.unpack_from('<H', v, pos + 8)[0]
    struct.pack_into('<H', v, pos + 8, flags & ~1)
    variants.append(('clear_encrypt', v))
    v = bytearray(data)
    namelen = struct.unpack_from('<H', v, pos + 28)[0]
    extraoff = pos + 46 + namelen
    extra = bytes(v[extraoff:extraoff + struct.unpack_from('<H', v, pos + 30)[0]])
    k = extra.find(b'\x01\x99\x07\x00')
    assert k >= 0
    # AES's inner compressor is offset + 9 of its 0x9901 record.
    struct.pack_into('<H', v, extraoff + k + 9, 99)
    variants.append(('nested_99', v))
    for name, blob in variants:
        path = base / (name + '.zip')
        path.write_bytes(blob)
        listing = run(UNZIP, '-Z', '-v', path).stdout
        assert b'malformed extra field / AES metadata' in listing, (name, listing)
        short = run(UNZIP, '-Z', '-1', path).stdout
        assert short
        test = run(UNZIP, '-tq', '-P', 'testpass', path, ok=(0, 1, 2, 3, 9, 81))
        assert test.returncode != 0, name


def main():
    for binary in (ZIP, UNZIP, DEDUP):
        if not binary.is_file():
            raise SystemExit('build before testing: ' + str(binary))
    with tempfile.TemporaryDirectory(prefix='iz-methods-') as name:
        base = pathlib.Path(name)
        payload = (b'Method 99 LZFSE and IBM CMPSC RefPtr fixture!\n' * 6000)
        # Files must be in CWD so archive member names are stable.
        import os
        old = os.getcwd()
        os.chdir(base)
        try:
            test_codec(base, 'lzfse', 99, payload)
            test_codec(base, 'cmpsc', 16, payload)
            test_method99_encryption(base, payload)
            test_invalid_aes_label(base)
        finally:
            os.chdir(old)
    print('PASS: LZFSE/CMPSC method 16/99 compression and RefPtr extraction')
    print('PASS: AE-1, AE-2, AE-3, ZipCrypto and method-99/AES separation')


if __name__ == '__main__':
    main()
