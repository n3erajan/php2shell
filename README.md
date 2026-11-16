# php2shell portable lab (CVE-2026-109618 / CVE-2026-109619)

A single Docker Compose target and one self-contained Python exploit. No
gdb, no host access, no WAF, no host-mounted files.

The target is deliberately made deterministic:

- `php:8.5.11-apache`, stock `php.ini` (`memory_limit=128M`).
- Exactly one Apache prefork worker, so every request hits the same process.
- ASLR disabled with `setarch x86_64 -R`, so the Zend MM chunk and
  `libphp.so` bases are fixed across container restarts.
- The docroot is created inside the container and owned by `www-data`.
  There is no host bind mount: the proof file exists only in the container
  and is read back over HTTP.

## Files

| File | Purpose |
| --- | --- |
| `docker-compose.yml` | Target container, single worker, ASLR off |
| `exploit.py` | The exploit (standard library only) |
| `README.md` | This file |

## Quick start

```sh
docker compose up -d
python exploit.py
```

Expected output:

```
[*] target http://127.0.0.1:8091/index.php
[*] command id>o1a2b3c4 -> /o1a2b3c4
[*] fixed bases heap=0x7ffff6800000 libphp=0x7ffff3200000
[*] fire table=0x7ffff68b30d8 system=0x7ffff37996e0 cmd=b'id>o1a2b3c4'
[+] RCE confirmed (fixed, attempt 1): uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Every run uses a fresh random output name, so a stale proof file can never
produce a false positive. The script requires `uid=` in the fetched body.

To use another port:

```sh
P2S_PORT=8092 docker compose up -d
python exploit.py --url http://127.0.0.1:8092/index.php
```

## Modes

`--mode auto` (default) fires at the known ASLR-off addresses. If that
misses, it leaks the real bases over HTTP and fires again. Use this if you
run the lab on a host whose kernel lays out the image differently.

`--mode fixed` only uses the hard-coded addresses. It is the fastest path
(two requests, ~1.5 MB of traffic) and works on the reference setup.

`--mode leak` always leaks first. It sends the stock 129 MiB field producer
and a forged `Set-Cookie` overread consumer (~65 MB of wire), recovers both
bases, then fires. This is also the path to use with ASLR **enabled**.

Useful flags:

```text
--cmd ls              custom command; stdout is auto-captured (14-byte max)
--fetch /o            proof path; single filename for auto-capture
--heap 0x...          override the fixed chunk base
--libphp 0x...        override the fixed libphp base
--repeat 2            fire attempts per address set
--leak-attempts 2     leak attempts in fallback mode
--quiet
```

The 14-byte command limit comes from the 167-byte fake HashTable: the
command starts at offset `0x98` and needs a terminating NUL.

## Custom commands and proofs

The chain gives you `system()` with **one shell command of at most 14
bytes**. There is no stdout channel back to the script, so `--cmd`
automatically appends a redirect into the container's docroot
(`/var/www/html`) and fetches the file back over HTTP:

```sh
python exploit.py --cmd ls
# actually runs: ls>o1a2b
# then fetches: /o1a2b
```

The proof filename is fresh for each run, so HTTP 200 is enough to prove
the shell ran, and the captured output is printed on success. Compound
commands are run in a subshell so all of their stdout is captured:

```sh
python exploit.py --cmd 'id;ls'            # (id;ls)>o1a2b
```

Add `--expect` for a content check:

```sh
python exploit.py --cmd whoami --expect www-data
```

Every character counts toward the 14-byte budget, including the redirect
and the filename: `(id;ls)>o1a2b` is 13 bytes, and a simple `ls -la>oa1b2`
is 12. If the command is too long, the script reports the minimum size it
needed.

If you want to choose the file yourself, include a redirect; the script
derives `--fetch` from a simple trailing `>name`:

```sh
python exploit.py --cmd 'ls>proof' --expect index.php
```

Relative paths resolve inside the container's docroot. The proof file is
not on the host: `exploit.py` retrieves it with an ordinary HTTP GET to the
target, so no filesystem, Docker, or gdb access is involved at exploit time.
For commands containing an explicit redirect, `--expect` still defaults to
`uid=` unless you override it.

## How it works

1. **OOM producer.** A multipart part carries a header block of 470,000
   duplicate 3-byte lines (`x:\n`). PHP allocates roughly 314 bytes of heap
   per header line, so ~1.4 MB of wire becomes ~147 MB of parser memory and
   aborts the request inside the RFC1867 upload-progress session. The abort
   leaves a stale `zend_reference` in `PS(http_session_vars)`.
2. **Dispatch consumer.** The next request sprays live 31-byte values whose
   data is a fake `zend_reference` pointing at the reclaimed session slot,
   plus 167-byte fake `zend_array` bodies. The array is shaped so
   `zend_hash_destroy` takes the static-keys branch and calls
   `pDestructor = zif_system` with `&bucket->val` as a fake
   `zend_execute_data`; `arg1` is a fake `zend_string` holding the command.
3. **Proof.** `system()` runs the command as `www-data`, writing its output
   into the container's docroot; the script fetches it back with a plain
   HTTP GET. No host or container access is used for the proof.

The leak mode uses the stock 129 MiB producer plus a consumer that forges
the session string length, making `Set-Cookie: PHPSESSID=...` overread
nearby pointers. The dominant 2 MiB-aligned value minus `zval_ptr_dtor`
gives the `libphp` base; the dominant pointer cluster gives the Zend MM
chunk base.

## Rebuild / reset

```sh
docker compose down
docker compose up -d
python exploit.py
```

Each `docker compose up` or `restart` recreates the docroot inside the
container, so proof files from earlier runs are discarded automatically.
There is nothing to clean on the host.

## Notes and limits

- Lab use only. Both the exploit and the target are intentionally
  vulnerable; do not expose the container to an untrusted network.
- The exploit needs only the target URL: proof retrieval is an HTTP GET.
  It never reads the host filesystem, the Docker socket, or container
  internals, and it does not use gdb.
- The fixed addresses (`0x7ffff6800000`, `0x7ffff3200000`) are the
  reference layout of this image under `setarch -R` on the tested host.
  A different host kernel may shift them. `--mode auto` handles that by
  leaking; `--heap` / `--libphp` allow manual overrides.
- The lab is amd64-only: the offsets and the fixed layout belong to the
  `linux/amd64` build of `php:8.5.11-apache`.
- `security_opt: seccomp=unconfined` is required on Linux hosts because the
  default Docker seccomp profile blocks the `personality(ADDR_NO_RANDOMIZE)`
  call that `setarch -R` makes.
- ASLR can be re-enabled by removing `setarch x86_64 -R` from the compose
  command; use `--mode leak` in that case.
- The chain targets `php:8.5.11-apache`. Other PHP builds need their own
  `zif_system`, `zval_ptr_dtor`, and chunk-relative table offset.

## Attribution

The OOM-session stale reference, the forged `Set-Cookie` overread, and the
167-byte fake-HashTable body follow Oracle-Security's public php-8.4.26 PoC
(no licence; wire shapes re-implemented). The chunk-relative dispatch
geometry and fixed-base measurements come from the dinosn php-cve research
this lab was extracted from. The count-based leak extraction and fill-only
worker rotation follow the ideas in `9bie/php2shell-bypass-aslr-exp`
(`pure/`).
