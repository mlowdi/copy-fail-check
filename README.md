# CVE-2026-31431 ("Copy Fail") — Safe Detector

A statically-compilable C tool that checks whether a Linux system is vulnerable to [CVE-2026-31431](https://copy.fail), the AF_ALG page-cache overwrite bug.

Designed for environments where Python isn't available — compile once, `scp` the binary, run it.

## The vulnerability

A 2017 optimization in `algif_aead.c` ([commit 72548b093ee3](https://github.com/torvalds/linux/commit/72548b093ee3)) made AEAD encrypt/decrypt operations run in-place, sharing source and destination scatterlists. When combined with `splice()`, file-backed page-cache pages end up in the writable destination scatterlist.

The `authencesn` algorithm rearranges Extended Sequence Number bytes using the destination buffer as scratch space. This scratch write lands directly in the page cache — a controlled 4-byte overwrite of any readable file's in-memory contents, requiring no privileges.

An attacker can use this to overwrite a SUID binary's page cache with shellcode and execute it for instant root.

- **Floor:** `torvalds/linux` commit `72548b093ee3` — August 2017, v4.14
- **Ceiling:** `torvalds/linux` commit `a664bf3d603d` — April 2026 (fix)
- **Fix:** separates source and destination scatterlists so page-cache pages stay read-only

## How this detector works

1. Creates a sentinel file in `/tmp` filled with a known pattern.
2. Reads it to populate the page cache.
3. Sets up an AF_ALG AEAD socket with `authencesn(hmac(sha256),cbc(aes))`.
4. Sends AAD containing a marker value ("PWND") as `seqno_lo`.
5. `splice()`s the sentinel's page-cache pages into the AEAD request.
6. Triggers decrypt via `recv()` — the scratch write fires before the expected auth-check failure.
7. Re-reads the sentinel from the page cache and checks for corruption.

**No system binaries are touched.** The only file modified is a user-owned temp file that is cleaned up on exit. The page-cache corruption is in-memory only — nothing is written back to disk.

## Building

Requires a Linux build host with GCC or musl-gcc. No external library dependencies.

```bash
# Static binary via musl (~30KB, ideal for deployment):
apt install musl-tools
make musl

# Static binary via glibc (~1MB):
make static

# Dynamic binary (for testing on a dev box):
make dynamic
```

## Usage

```bash
# Copy to target and run:
scp af_alg_check target-host:
ssh target-host ./af_alg_check
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | NOT vulnerable (precondition not met, or page cache intact) |
| `1`  | Test error (could not complete the check — see stderr) |
| `2`  | VULNERABLE (page-cache corruption detected) |

### Example output

**Vulnerable system:**
```
[*] CVE-2026-31431 detector  kernel=6.8.0-57-generic  arch=x86_64
[+] AF_ALG + authencesn(hmac(sha256),cbc(aes)) loadable — precondition met.
[!] VULNERABLE to CVE-2026-31431.
[!]   Marker "PWND" (AAD seqno_lo) landed in the spliced page-cache page at offset 24.
[!]   Surrounding bytes: 000000000000000050574e4400000000
[!] Apply the upstream fix or block algif_aead.
```

**Patched system:**
```
[*] CVE-2026-31431 detector  kernel=6.12.25-0-generic  arch=x86_64
[+] AF_ALG + authencesn(hmac(sha256),cbc(aes)) loadable — precondition met.
[+] Page cache intact. NOT vulnerable on this kernel.
```

## Mitigation

Until the kernel is patched, block the vulnerable algorithm from being loaded by unprivileged users:

```bash
echo "install algif_aead /bin/true" > /etc/modprobe.d/cve-2026-31431.conf
rmmod algif_aead 2>/dev/null
```

This prevents the `algif_aead` kernel module from loading, closing the attack vector. It may affect IPsec configurations that rely on ESN — check before applying in production.

## References

- [copy.fail](https://copy.fail) — Disclosure site
- [xint.io writeup](https://xint.io/blog/copy-fail-linux-distributions) — Technical analysis
- [rootsecdev/cve_2026_31431](https://github.com/rootsecdev/cve_2026_31431) — Python PoC and safe test (this tool is a C port of the test)

## License

MIT
