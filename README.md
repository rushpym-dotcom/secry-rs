# secry

Secure token encryption CLI. Encrypt text, files and secrets with modern authenticated encryption.

## Install

```sh
cargo install secry
```

Also available via npm and pip:
```sh
npm install -g secry
pip install secry
```

Both `secry` and `sec` commands are available after install.

## Algorithms

| Flag   | Algorithm              | Nonce   |
|--------|------------------------|---------|
| (none) | AES-256-GCM            | 96-bit  |
| --v2   | ChaCha20-Poly1305      | 96-bit  |
| --v3   | XChaCha20-Poly1305     | 192-bit |

All versions use scrypt (N=16384, r=8, p=1) for key derivation.

## Usage

```sh
# encrypt
secry enc "text" --sw password
secry enc "text" --sw password --v2
secry enc "text" --sw password --v3 --expires 24h
secry enc "text" --sw password --compact      # shorter token with sec: prefix

# decrypt  (accepts secry:, sec: and legacy rwn64: tokens)
secry denc "secry:v1:..." --sw password
secry denc "sec:v1:..."   --sw password
secry denc "rwn64:v1:..."  --sw password

# verify token
secry verify "secry:v1:..." --sw password

# generate password
secry gen 32
secry gen 32 --upper --count 5

# fingerprint
secry fp "text" --sw secret

# one-way seal
secry seal "text" --sw secret
secry seal "text" --sw secret --compact
secry seal-verify "text" --sw secret --token "secry:s1:..."

# inspect token
secry info "secry:v1:..."

# sec alias — identical to secry
sec enc "text" --sw password
sec enc "text" --sw password --compact
```

## Token format

```
secry:v1:   AES-256-GCM           (full)
secry:v2:   ChaCha20-Poly1305     (full)
secry:v3:   XChaCha20-Poly1305    (full)
secry:s1:   HMAC-SHA256 seal      (one-way, full)
secry:s2:   BLAKE3 seal           (one-way, full)

sec:v1:     AES-256-GCM           (compact)
sec:v2:     ChaCha20-Poly1305     (compact)
sec:v3:     XChaCha20-Poly1305    (compact)
sec:s1:     HMAC-SHA256 seal      (one-way, compact)
sec:s2:     BLAKE3 seal           (one-way, compact)

rwn64:v1:   legacy (still accepted by denc/verify/info)
```

**Compact mode** (`--compact`) uses smaller salt and nonce, producing shorter tokens at the cost of slightly reduced security margin. Use full mode for high-security scenarios.

## License

MIT
