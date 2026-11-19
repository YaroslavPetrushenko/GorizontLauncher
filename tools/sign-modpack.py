r"""Signs modpack.zip for the launcher.

Usage:
  python tools/sign-modpack.py --zip modpack.zip --key %USERPROFILE%\.gorizont-keys\pack-signing.key

Writes modpack.sig next to the zip: base64 Ed25519 signature over the SHA-256 digest of the zip.
Upload BOTH modpack.zip and modpack.sig to the same GitHub release.
The private key must never be committed to the repository.
"""
import argparse, base64, hashlib, os, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--zip', required=True)
    ap.add_argument('--key', default=os.path.join(os.path.expanduser('~'), '.gorizont-keys', 'pack-signing.key'))
    args = ap.parse_args()
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(open(args.key).read().strip()))
    h = hashlib.sha256()
    with open(args.zip, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    sig = key.sign(h.digest())
    out = os.path.join(os.path.dirname(os.path.abspath(args.zip)), 'modpack.sig')
    with open(out, 'w') as f:
        f.write(base64.b64encode(sig).decode() + '\n')
    print('wrote', out)

if __name__ == '__main__':
    sys.exit(main())
