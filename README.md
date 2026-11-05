# sshole-check

Audit and interim-mitigation tool for **CVE-2026-123158 ("\*SSHole")**, an OpenSSH password authentication bypass on musl-based Linux (Alpine). It covers your **running Docker containers, local images and the host**.

Example output (abridged, from a test machine):

```
$ sudo ./sshole-check.sh --images
CVE-2026-123158 (*SSHole) audit · sshole-check 1.0.0 · 2026-11-05 22:45:52 UTC

[VULN  ] container sshole-real ghcr.io/requarks/wiki:2.5
                   OpenSSH 10.3p1 · openssh-server-10.3_p1-r1 openssh-server-common-10.3_p1-r1 · alpine 3.24.3
                   PasswordAuthentication=yes · PAM=off · PermitRootLogin=prohibit-password · port: 22
                   '*' accounts: root carol · $5$/$6$ hashed: bob
                   sshd running: yes · published: 22→0.0.0.0:33776 [::]:33776
                   → unpatched (package older than 10.3_p1-r2, the Alpine 3.24 fix) and all conditions are met
                   · root is '*' but PermitRootLogin=prohibit-password, root cannot log in with a password
                   · sshd is running and published to the outside
[WARN  ] image     docker.gitea.com/gitea:1.24.4 dd29b53ab011
                   OpenSSH 10.0p2 · openssh-server-10.0_p1-r7 openssh-server-common-10.0_p1-r7 · alpine 3.22.1
                   PasswordAuthentication=yes · PAM=off · PermitRootLogin=without-password · port: 22
                   '*' accounts: root git · $5$/$6$ hashed: -
                   EXPOSE 22/tcp 3000/tcp
                   → unpatched (package older than 10.0_p1-r11, the Alpine 3.22 fix); conditions not met right now, becomes exploitable once an account gets a password
[OK    ] container postgres postgres:16-alpine
                   no sshd

Summary: OK=339 WARN=8 VULN=1 BREACH=0 SKIPPED=11
```

> **It never tries to log in.** The probe only reads the sshd binary, `sshd -T` / `sshd_config`, `/etc/shadow`, the apk database and log files inside each target. Read the script before running it; it is a single file of plain bash and POSIX sh.

---

## Quick start

```sh
curl -fsSLO https://raw.githubusercontent.com/ersinkoc/sshole-check/main/sshole-check.sh
less sshole-check.sh            # read it first
chmod +x sshole-check.sh
sudo ./sshole-check.sh          # running containers + host
sudo ./sshole-check.sh --images # also every local image
```

Requirements: `bash` on the machine that runs it, plus access to the Docker (or Podman) CLI. The targets only need `/bin/sh`. Images with no shell, such as distroless or scratch images, are reported as `SKIP`; they cannot run sshd anyway.

---

## About CVE-2026-123158

| | |
|---|---|
| **Name** | \*SSHole / "sshhole" |
| **Component** | OpenSSH `sshd`, password authentication without PAM |
| **Platform** | Linux + **musl libc** (Alpine, also OpenWrt / Buildroot / Yocto builds) |
| **Fixed in** | OpenSSH **10.6p2** (2026-11-05), plus Alpine backports to every branch from 3.16 on |
| **CVSS 3.1** | **8.1 High**, `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-394 (Unexpected Status Code or Return Value) |
| **GHSA** | [GHSA-4fcc-vm97-gx3x](https://github.com/advisories/GHSA-4fcc-vm97-gx3x) |
| **Reported by** | Özgün Kültekin ([Wakefield](https://wakefield.co)) |

### What goes wrong

Three behaviours that are each reasonable on their own add up to a login bypass:

1. **musl `crypt()` returns `"*"` on failure.** Since 2012 musl returns a failure string instead of `NULL`. Its SHA-crypt implementation refuses keys longer than 256 bytes (`KEY_MAX`, a DoS guard), so a password longer than 256 bytes hashes to the literal string `*`.
2. **OpenSSH hashes the password even when the account has no usable hash.** Since the CVE-2016-6210 user-enumeration fix, when the stored password field is too short to contain a salt, sshd borrows the salt and settings of **another account's real `$5$`/`$6$` hash** so that timing looks the same. That is why a second, password-protected account is needed.
3. **Alpine base images ship `root:*`.** Since Alpine 3.16 (2022), `*` is the "no password, keys only" marker for root. The same marker is used for key-only users, directory-service users (nslcd, sssd, winbind) and the `alpine` user in tiny-cloud images.

Without PAM, sshd compares `crypt(password, borrowed_salt)` with the stored field. For a 257 to 1024 byte password that is `"*" == "*"`, and the login is **accepted**.

OpenSSH 10.6p2 works around it by rejecting stored hashes that are too short to be valid. The underlying behaviour in musl is unchanged; the fix is in sshd.

### You are vulnerable only if **all** of these hold

- [x] `sshd` is OpenSSH < 10.6p2 **without** the Alpine backport, linked against **musl**
- [x] Password checks don't go through PAM: the `openssh-server` package, or `openssh-server-pam` with `UsePAM no`
- [x] `PasswordAuthentication yes` (the **default**)
- [x] At least one account whose shadow password field is exactly `*` (a `!` lock is **not** affected)
- [x] At least one **other** local account with a `$5$` or `$6$` hash
- [x] The attacker can reach the SSH port

Root itself is only reachable with `PermitRootLogin yes`; the default `prohibit-password` blocks password logins for root. On Alpine's AWS/Azure tiny-cloud images, though, the `*` user `alpine` has **passwordless `doas`**, so getting in as `alpine` means getting root.

**Not affected:** glibc distributions (Debian, Ubuntu, RHEL, Fedora …), `UsePAM yes`, `PasswordAuthentication no`, containers that don't run sshd, Dropbear, and OpenBSD's sshd.

### Fixed versions

| Alpine branch | First fixed `openssh` | Fixed point release |
|---|---|---|
| edge | `10.6_p2-r0` | – |
| 3.24 | `10.3_p1-r2` | **3.24.4** |
| 3.23 | `10.2_p1-r1` | **3.23.8** |
| 3.22 | `10.0_p1-r11` | **3.22.8** |
| 3.21 | `9.9_p2-r1` | **3.21.10** |
| 3.20 | `9.7_p1-r6` | (EOL, package only) |
| 3.19 | `9.6_p1-r3` | (EOL, package only) |
| 3.18 | `9.3_p2-r4` | (EOL, package only) |
| 3.17 | `9.1_p1-r7` | (EOL, package only) |
| 3.16 | `9.0_p1-r6` | (EOL, package only) |

Alpine **backported** the fix, so most branches keep their old upstream version: a fixed 3.24 box still reports `OpenSSH_10.3p1`. **`sshd -V` alone cannot tell you whether you are patched.** That is why this tool compares the apk package release against the table above.

---

## Why Docker is a special case

- `apk upgrade` on a running container is lost when the container is recreated. The **image** is what you have to fix.
- Base images pinned to an old tag (`alpine:3.22.1`, `FROM node:20-alpine@sha256:…`) keep the vulnerable package forever, and a rebuild with cache can reuse the old `apk add` layer.
- An image can be "not exploitable right now" (no `$6$` account yet) and still become exploitable as soon as an entrypoint script runs `chpasswd`. sshole-check reports this as **WARN**.
- A container on `--network host`, or with `-p 22:22` / `-p 2222:22`, puts the bug on the network. sshole-check shows the published mapping for each container.

---

## What it checks

For every target it runs a small POSIX `sh` probe inside it. Containers are probed with `docker exec -u 0`. Images are started with `docker run --rm --network none --entrypoint sh -u 0`. The host is probed directly.

| Check | How |
|---|---|
| libc | `/lib/ld-musl-*` present |
| sshd + version | `sshd -V` |
| Patched? | upstream version ≥ 10.6p2 **or** apk package ≥ the fixed release for the target's Alpine branch (`apk version -t`) **or**, as a fallback, the package build date is after 2026-11-05 |
| Effective config | `sshd -T` (with a throwaway host key in a temp dir if the image has none yet), falling back to parsing `sshd_config` + `sshd_config.d/*.conf` |
| PAM | sshd / sshd-session linked against `libpam` **and** `UsePAM yes` |
| Accounts | `/etc/shadow`: accounts with exactly `*`, accounts with `$5$`/`$6$` hashes |
| Root | `PermitRootLogin` must be `yes` for `root:*` to count |
| Exposure | running sshd, `docker port` mappings, host network, image `EXPOSE` |
| Evidence | `Accepted password for <user>` in `/var/log/{messages,auth.log,secure}` and optionally in `docker logs`, matched against the `*` accounts |

### Verdicts

| Verdict | Meaning |
|---|---|
| `OK` | No sshd, not musl, patched, or PAM in use |
| `WARN` | Unpatched, but not exploitable **right now** (password auth off, no `$5$`/`$6$` account, only `root:*` with `prohibit-password`, or shadow unreadable) |
| `VULN` | Unpatched and every condition is met |
| `BREACH` | A successful password login was logged for an account whose password field is `*`. Treat the target as **compromised** |
| `SKIP` | Not musl (host), no shell, or exec failed |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean |
| `1` | At least one `WARN` |
| `2` | At least one `VULN` or `BREACH` |
| `64` | Bad command-line option |

---

## Usage

```
sshole-check.sh [options]

Scan targets:
  (default)          running containers + host
  --images, --all    also scan local images (each started briefly with --network none)
  --no-host          skip the host
  --no-containers    skip running containers

Extra checks:
  --logs             scan `docker logs` for "Accepted password for"
  --online           inside containers, compare installed openssh with the apk repo (needs network)

Interim mitigation (running containers only, asks before each change):
  --mitigate         prepend "PasswordAuthentication no" to sshd_config and reload sshd
  --upgrade          upgrade openssh packages via apk and reload sshd

Output:
  -y, --yes          don't ask for confirmation
  -q, --quiet        only print targets with problems
  -V, --version      print version
  -h, --help         this help

Environment:
  DOCKER=podman      use another docker-compatible CLI
```

### Examples

```sh
# Everything, only show problems
sudo ./sshole-check.sh --images --logs -q

# Podman
sudo DOCKER=podman ./sshole-check.sh

# Just the images (e.g. on a build server / in CI)
./sshole-check.sh --no-host --no-containers --images -q || echo "fix your images"

# Hot-fix running containers: upgrade openssh, then disable password login
sudo ./sshole-check.sh --upgrade --mitigate

# Alpine host without bash
apk add bash && sudo bash sshole-check.sh --no-containers
```

### Interim mitigations (`--upgrade`, `--mitigate`)

Both only touch **running containers** that are not already fixed and not using PAM, and both ask before every change unless you pass `-y`.

- `--upgrade` runs `apk update && apk add -u <installed openssh packages>`, validates the config with `sshd -t`, and sends `SIGHUP` to the sshd listener. sshd then re-executes itself, so the **new binary is running** without dropping the container, even when sshd is PID 1.
- `--mitigate` backs up `/etc/ssh/sshd_config` to `sshd_config.sshole.bak` and prepends `PasswordAuthentication no`. The first value sshd reads wins, so this also beats `Include`d drop-ins. It then validates with `sshd -t` (and rolls back if that fails), reloads sshd, and warns if a `Match` block re-enables password auth. **Make sure key-based login works for the accounts you need first.**

Both changes are **temporary**: they are gone when the container is recreated.

---

## Permanent fix

```dockerfile
FROM alpine:3.24.4          # or 3.23.8 / 3.22.8 / 3.21.10 or later
RUN apk upgrade --no-cache  # always pull the latest security fixes
```

```sh
docker build --pull --no-cache -t myimage .
docker compose up -d --force-recreate
```

On an Alpine host or VM:

```sh
apk upgrade -U -a
rc-service sshd restart      # upgrading the package does NOT restart the running sshd
```

Defence in depth, which is worth doing whatever this CVE says:

- `PasswordAuthentication no` (for example in `/etc/ssh/sshd_config.d/00-no-passwords.conf`), then check with `sshd -T | grep -i passwordauthentication`
- Don't publish SSH from containers to the internet. Use `docker exec`, a bastion or a VPN instead.
- Lock unused accounts with `!` instead of `*`, and audit passwordless `doas`/`sudo` rules.

### If you get a `BREACH`

An `Accepted password for <user>` line for a `*` account cannot come from a legitimate login. Isolate the container or host from the network, keep it (don't just recreate it) for forensics, and review `doas`/`sudo` usage, new users, `authorized_keys`, cron jobs and recently modified files. Then rotate any secrets the target could reach.

---

## Limitations

- **Logs.** Alpine containers rarely run syslog. `--logs` only helps if sshd logs to stdout/stderr (`sshd -D -e`). A missing log line proves nothing, and an attacker with root can delete logs.
- **Static analysis.** An image can become vulnerable at runtime, for example when an entrypoint sets a password. That case is reported as `WARN`, not `OK`.
- **Non-Alpine musl** (OpenWrt, Buildroot, Yocto, custom builds): there is no apk database, so the verdict relies on the upstream version (< 10.6p2 = unpatched). Vendor backports there are not detected.
- **Kubernetes** isn't covered directly. Run it on each node, or use `--images` against the images you deploy.
- The `*`-account check matches the field **exactly** `*`, which is the case the advisories describe. Review unusual lock markers by hand.

---

## References

- OpenSSH 10.6p2 release notes: <https://www.openssh.org/releasenotes.html#10.6p2>
- OpenSSH fix commit: <https://github.com/openssh/openssh-portable/commit/4353fdc43ef646c43a8dda7025cc1a898caf1482>
- Alpine Linux advisory: <https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass>
- GitHub Advisory GHSA-4fcc-vm97-gx3x: <https://github.com/advisories/GHSA-4fcc-vm97-gx3x>
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-123158>
- Original research: <https://sshhole.com>
- OX Security write-up: <https://www.ox.security/blog/openssh-authentication-bypass-cve-2026-123158/>
- Lab environments: [leonjza/sshhole-lab](https://github.com/leonjza/sshhole-lab), [predkambrij/sshhole-repro](https://github.com/predkambrij/sshhole-repro)
- Damien Miller's announcement: <https://hachyderm.io/@damienmiller/117563026759098135>

## License

MIT. See [LICENSE](LICENSE). Provided as is, without warranty: run it against systems you are responsible for, and read it before you do.
