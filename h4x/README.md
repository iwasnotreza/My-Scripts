# H4xScripts loader — reverse engineering notes

Target: `https://h4xscripts.xyz/loader`  
Scope: **static analysis only**. Nothing in this folder executes the loader inside Roblox.

## What the URL actually returns

It is not a plain game script. It is a multi-stage, encrypted Lua loader/VM wrapper:

1. A small Lua bootstrap builds a 32-byte root key from eight `bit32` seeds.
2. A custom base64 alphabet decodes a large binary container.
3. The container is split into 102 varint-framed records:
   - tag `66`: stage 1, 61 parts, 157059 encrypted bytes;
   - tag `48`: stage 2, 41 parts, 113450 encrypted bytes.
4. Each stage is HMAC-SHA256 verified and ChaCha20 decrypted.
5. Stage 1 decrypts to a 32-byte inner key plus range-coded data, which expands to 210254 bytes of Lua.
6. Stage 2 uses a key derived from the root key, inner key, and SHA256 of the stage 1 Lua.

Observed root key:

```text
d99d8bedfdf41fd78eb2c8fef17bcf83fbdd90e29a0df8613b7af68d8c789295
```

Observed custom alphabet:

```text
6xeA2NrCkf/tImOgPnuYBqoJTcHw04i9dyQXb5G7LD3ESz+RvMj8hWUZ1alKsFpV
```

## Files

- `decode_loader.py` — static Python decoder. It parses the wrapper, verifies HMAC, decrypts ChaCha20, range-decodes stage 1, and writes:
  - `stage1.lua`
  - `stage2.bin`
  - `keys.json`
  - `strings.txt`
- `fetch_raw.lua` — optional executor helper that only HTTP GETs the loader and saves `raw_loader.lua`. It does **not** execute the loader.
- `dump_stages.lua` — optional runtime dumper hooking `loadstring`/`load`. Use only if you accept runtime analysis; it is not needed for the static decoder.

## Usage

Save the raw HTTP body as `h4x/raw_loader.lua`, then run:

```bash
python3 h4x/decode_loader.py h4x/raw_loader.lua -o h4x/out
```

The decoder does not execute Lua. It only parses and decrypts the observed container format.

## Current status

The decoder and container format are implemented and the ChaCha20 core matches RFC 8439 test vectors. The sandbox cannot directly download `h4xscripts.xyz`, so the raw loader body must be supplied by the user (for example with `fetch_raw.lua`) before the final decoded stage files can be generated.

## Safety

Do not run unknown loaders in a real executor unless you trust the source. This toolkit is for static reverse engineering and does not require executing the payload.
