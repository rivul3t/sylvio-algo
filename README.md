This repository contains a simple Sylvio-style infector/payload proof-of-concept. The infector XOR-encrypts the target program's `.text` section, injects an executable payload and the XOR key into the binary, and rewrites the ELF `e_entry` to point to the payload. When the infected binary runs, the payload prints a banner, calls `mprotect` to make the target code writable, decrypts the `.text` (XOR with the stored key), restores registers and jumps to the original entry point (OEP) so the host program continues normally.

---

## Detailed behavior

### Infector (C side)

1. Determine or read ELF metadata: `orig_entry`, `parasite_offset`, `text_seg_off`, `text_seg_size` (or `filesz`) and related values.
2. Generate a 16‑byte key (`generate_key(info)`).
3. XOR-encrypt the target region (usually `.text`) in the file: `cipher = plain XOR key` and write the modified bytes back to the file.
4. Patch the assembly payload: replace hard-coded placeholders with real values (offsets, sizes, OEP/patch constants).
5. Insert the payload (and the key, or the key offset) into the file at `parasite_offset`.
6. Modify the ELF `e_entry` to `parasite_offset` so process execution starts in the payload.

### Payload (runtime)

1. Save registers used by the payload.
2. Print the banner (e.g. `....WOODY....\n`).
3. Use a RIP-relative trick (call + read \[rsp]) to determine the payload's runtime location and compute base addresses using patched constants.
4. Call `mprotect` on the pages covering the encrypted area so memory becomes writable.
5. Read the key (payload either contains the key or knows the offset where the key is stored).
6. XOR the `rsi` bytes starting at `rdi` with the key (wrap key every 16 bytes): `cipher XOR key = plain` — this restores `.text` in memory.
7. Restore registers and jump to the original entry point (push rax; ret) so the host binary continues execution normally.

---

## Placeholders inside `xor_cipher.s`

The assembly payload uses a set of patchable constants. The infector must replace these placeholders with correct values before writing the payload into the target binary:

* `0x14141414` — `text_seg_size` (size of the region for mprotect / XOR).
* `0x22222222` — filesz / XOR length (may be same as `text_seg_size`).
* `0x33333333` — file offset (so runtime start address = `base + file_offset`).
* `0x44444444` — key length (usually 16).
* `0x55555555` — key offset (so runtime key address = `base + key_offset`).
* `0x48484848` — location inside the payload where the infector can write the key (or a signature/marker used to locate the key insertion point).
* `0x71717171`, `0x72727272`, `0x73737373` — placeholders used in the `_ret2oep` expression to compute `orig_entry`. The infector should compute and patch values such that the expression in `_ret2oep` yields the original entry point address.

---

## How to assemble the payload into a flat binary and produce a C-style `\\x..` string

1. Assemble the payload into a flat binary (no ELF header):

```bash
nasm -f bin payloads/xor_cipher.s -o payload.bin
```

2. Convert the binary to a C-escaped `\\xHH` string for embedding into source code:

```bash
# Option A (xxd + sed)
xxd -p payload.bin | tr -d '\\n' | sed 's/../\\\\x&/g' > payload_hex.txt

# Option B (hexdump)
hexdump -v -e '/1 "\\\\x%02x"' payload.bin > payload_hex.txt
```

3. Paste the produced `payload_hex.txt` contents into your C source as:

```c
unsigned char pload[] = "\\x50\\x51...";
size_t pload_size = sizeof(pload); // note: sizeof includes the terminating zero if you used a string literal
```

4. Get exact binary size:

```bash
wc -c payload.bin
```

> Important: `"\\x00"` bytes inside a C string are valid binary zeros; `sizeof(pload)` may include an extra terminating zero if you inserted the bytes as a string literal. For the exact payload size, prefer `wc -c payload.bin` or read the binary file directly in the infector instead of embedding as a C string literal.

---

## Typical patch + key-insertion flow (infector pseudocode)

1. `generate_key(info)` — produce 16 random bytes.
2. Patch size/offset placeholders in the payload blob:

```c
patch32(info->parasite_code, info->parasite_size, 0x14141414, (int32_t)info->text_seg_size);
// patch other placeholders similarly
```

3. Encrypt target `.text` in the mapped file buffer:

```c
_xor(file + info->orig_entry, info->text_seg_size, info->key, KEY_LEN);
```

4. Find the `0x48484848` location inside the payload and `memcpy` the key there (or store the key immediately after the payload in the file):

```c
size_t key_offset = find_32bits(info->parasite_code, info->parasite_size, 0x48484848);
memcpy(info->parasite_code + key_offset, info->key, KEY_LEN);
```

5. Copy payload and key into the file at `parasite_offset`:

```c
memcpy(file + info->parasite_offset, info->parasite_code, info->parasite_size);
memcpy(file + info->parasite_offset + info->parasite_size, info->key, KEY_LEN);
```

6. Patch ELF `e_entry` to point to `parasite_offset`.

---

## Example build commands

```bash
# build payload flat binary
nasm -f bin payloads/xor_cipher.s -o payload.bin
xxd -p payload.bin | tr -d '\\n' | sed 's/../\\\\x&/g' > payload_hex.txt

# build infector
gcc -Wall -O2 src/*.c -o infector
```
