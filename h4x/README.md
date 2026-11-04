# H4xScripts loader — reverse engineering notes

Target: `https://h4xscripts.xyz/loader`  
Scope: **static analysis only**. Nothing in this folder executes the loader inside Roblox or a real executor.

## Result

The uploaded raw loader (`h4x/raw_loader.lua`, 395,823 bytes) has been decoded. The decoded artifacts are in `h4x/out/`:

| File | Size | Meaning |
|---|---:|---|
| `h4x/out/stage1.lua` | 212,860 B | First Lua stage: an obfuscated custom VM / loader interpreter. |
| `h4x/out/stage2.bin` | 116,094 B | Second stage after HMAC verification and ChaCha20 decryption. It is VM bytecode / data consumed by `stage1.lua`, not plain readable Lua. |
| `h4x/out/keys.json` | — | Derived keys, hashes, alphabet, and parsed container parameters. |
| `h4x/out/strings.txt` | — | Printable strings extracted from both decoded stages. |

Important: this removes the outer HTTP/loader encryption. The remaining payload is still protected by a custom VM and additional per-function encryption/compression inside `stage1.lua`.

## Container format observed in this build

1. A Lua bootstrap builds a 32-byte root key from eight `bit32` seeds.
2. A custom base64 alphabet decodes a large binary container.
3. The container is split into **104** varint-framed records. Each record is framed as:

   ```text
   index, tag, length, body[length]
   ```

   - tag `106`: stage 1, **59** parts, **158,550** encrypted bytes;
   - tag `80`: stage 2, **45** parts, **116,138** encrypted bytes.

4. Each stage blob is:

   ```text
   nonce[12] || ciphertext || HMAC-SHA256 tag[32]
   ```

   The HMAC authenticates `nonce || ciphertext`.

5. Keys are derived with HMAC-SHA256 from the root key and 16-byte domain separators:

   ```text
   enc_key = HMAC(root, DS_ENC || nonce)
   mac_key = HMAC(root, DS_MAC || nonce)
   tag     = HMAC(mac_key, DS_TAG || nonce || ciphertext)
   ```

6. ChaCha20 decrypts the ciphertext with counter starting at 1.
7. Stage 1 plaintext is:

   ```text
   inner_key[32] || range-coded Lua
   ```

   The range-coded data expands to **212,860** bytes of Lua.

8. Stage 2 key is derived from the root key, inner key, and SHA256 of the decoded stage 1 Lua:

   ```text
   k1 = HMAC(root, DS_STAGE1_KEY || inner_key)[0:32]
   stage2_key = HMAC(k1, DS_STAGE2_KEY || inner_key || SHA256(stage1_lua))[0:32]
   ```

## Observed values for the uploaded build

Root key:

```text
8701315949d7f75c871e1d49aea23c98059421b8a5415eb421fde4cdeaede4e6
```

Custom alphabet:

```text
IpePMLU804HcaZVOQCgyo2bTuE5fNhA/Fr1lDSR7vkjqist6J+Xn39BzwYmWGxKd
```

Domain separators:

```text
DS_ENC        = 046ea8547a444029da19b5cc341fec98
DS_MAC        = 181f27ebd1c5b1e97abfe1b495eea842
DS_TAG        = 5d3c84624a33f6c12df521bacfe722c9
DS_STAGE1_KEY = a83f9b0210570a8067c6a7ca93715ff3
DS_STAGE2_KEY = cf5dc50b03f6022a12a1053d4e05540f
```

Hashes:

```text
container_sha256 = e9789c4f72f131982e2f2683eb7c1589b3304d95ce8cb7a3f9c180d361796d09
stage1_sha256    = af8487eb797ff41f93dbc0a815477daf83d07a0ed2f0cba79d4f1602f7e9b4f4
stage2_sha256    = fe90320309cff1994bc9bda37a7460b6383e4b834cc0a9ae098acb169d807eec
```

## Files

- `raw_loader.lua` — the uploaded raw loader body.
- `decode_loader.py` — static Python decoder. It parses the wrapper constants from the raw Lua, verifies HMAC, decrypts ChaCha20, range-decodes stage 1, and writes the decoded artifacts.
- `out/` — decoded output for this build.
- `fetch_raw.lua` — optional executor helper that only HTTP GETs the loader and saves `raw_loader.lua`. It does **not** execute the loader.
- `dump_stages.lua` — optional runtime dumper hooking `loadstring`/`load`. Use only if you accept runtime analysis; it is not needed for the static decoder.

## Usage

```bash
python3 h4x/decode_loader.py h4x/raw_loader.lua -o h4x/out
```

The decoder does not execute Lua. It only parses, decrypts, and decompresses the container.

## Safety

Do not run unknown loaders in a real executor unless you trust the source. This toolkit is for static reverse engineering and does not require executing the payload.
