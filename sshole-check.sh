#!/usr/bin/env bash
# sshole-check.sh — audit / interim-mitigation tool for CVE-2026-123158 ("*SSHole")
#                   across Docker containers, local images and the host.
#
# Vulnerable: OpenSSH < 10.6p2 built against musl libc (Alpine etc.). ALL of these are required:
#   - sshd does password checks without PAM (openssh-server, or openssh-server-pam with UsePAM no)
#   - PasswordAuthentication yes (the default)
#   - an account whose password field is exactly "*" (root:* in Alpine base images)
#   - at least one other account with a $5$/$6$ password hash
#
# This tool never attempts a login. It only reads binaries, config, /etc/shadow and logs.
#
# Usage:
#   ./sshole-check.sh               running containers + host
#   ./sshole-check.sh --images      + local images (each image is started briefly with --network none)
#   ./sshole-check.sh --logs        + scan `docker logs` for "Accepted password for"
#   ./sshole-check.sh --online      compare installed openssh with the apk repo inside containers (needs network)
#   ./sshole-check.sh --mitigate    on at-risk containers: PasswordAuthentication no + reload sshd
#   ./sshole-check.sh --upgrade     on at-risk containers: upgrade openssh packages + reload sshd
#   --no-host  --no-containers  -y (don't ask)  -q (only show problems)  -h (help)
#
#   DOCKER=podman ./sshole-check.sh   (use podman)
#
# --mitigate / --upgrade are TEMPORARY: they are lost when the container is recreated.
# Permanent fix: rebuild the image with --pull --no-cache and recreate the containers.
#
# Exit code: 0 clean · 1 warnings · 2 vulnerable target or suspicious login found

# Re-launch under bash if invoked via sh/dash/busybox
if [ -z "${BASH_VERSION:-}" ]; then
  if command -v bash >/dev/null 2>&1; then exec bash "$0" "$@"; fi
  echo "This script requires bash. On Alpine: apk add bash  —  then: bash $0" >&2
  exit 1
fi

set -uo pipefail

VERSION="1.0.0"
DOCKER="${DOCKER:-docker}"
FIX_VER="10.6p2"
# Fallback heuristic only (used when the Alpine branch is unknown): openssh packages
# built after 2026-11-05 00:00 UTC are assumed to contain the fix.
FIX_EPOCH=1793836800
# First fixed `openssh` package per Alpine branch (Alpine advisory, 2026-11-05).
FIXED_TABLE="edge=10.6_p2-r0 3.24=10.3_p1-r2 3.23=10.2_p1-r1 3.22=10.0_p1-r11 3.21=9.9_p2-r1 3.20=9.7_p1-r6 3.19=9.6_p1-r3 3.18=9.3_p2-r4 3.17=9.1_p1-r7 3.16=9.0_p1-r6"

DO_CONTAINERS=1; DO_HOST=1; DO_IMAGES=0; DO_LOGS=0; DO_ONLINE=0
DO_MITIGATE=0; DO_UPGRADE=0; YES=0; QUIET=0

usage(){
  cat <<'EOF'
sshole-check.sh — audit / interim-mitigation tool for CVE-2026-123158 ("*SSHole")

Usage: sshole-check.sh [options]

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

Exit code: 0 clean · 1 warnings · 2 vulnerable target or suspicious login found

--mitigate / --upgrade are TEMPORARY and are lost when the container is recreated.
Permanent fix: rebuild images with --pull --no-cache and recreate the containers.
EOF
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --images|--all)   DO_IMAGES=1 ;;
    --logs)           DO_LOGS=1 ;;
    --online)         DO_ONLINE=1 ;;
    --mitigate)       DO_MITIGATE=1 ;;
    --upgrade)        DO_UPGRADE=1 ;;
    --no-host)        DO_HOST=0 ;;
    --no-containers)  DO_CONTAINERS=0 ;;
    -y|--yes)         YES=1 ;;
    -q|--quiet)       QUIET=1 ;;
    -V|--version)     echo "sshole-check $VERSION"; exit 0 ;;
    -h|--help)        usage ;;
    *) echo "Unknown option: $1 (see -h)" >&2; exit 64 ;;
  esac
  shift
done

if [ -t 1 ]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; M=$'\e[35m'; B=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'
else
  R=; G=; Y=; M=; B=; D=; N=
fi

TMO=""; command -v timeout >/dev/null 2>&1 && TMO="timeout 60"

N_OK=0; N_WARN=0; N_VULN=0; N_ALERT=0; N_SKIP=0
RISKY=()          # "id|name|mpid|pa|fixed"
CUR_ID=""; CUR_MPID=""

# ---------------------------------------------------------------------------
# POSIX sh probe executed inside the target (container / image / host).
# Read-only apart from a temporary host key in a mktemp dir (removed again).
# Output: key=value lines.
# ---------------------------------------------------------------------------
PROBE_BODY=$(cat <<'EOF'
ID=unknown
[ -r /etc/os-release ] && . /etc/os-release 2>/dev/null
echo "os=${ID:-unknown}"
AREL=""
[ -r /etc/alpine-release ] && AREL=$(cat /etc/alpine-release) && echo "alpine_release=$AREL"
if ls /lib/ld-musl-* >/dev/null 2>&1; then echo musl=yes; else echo musl=no; fi

SSHD=""
for c in /usr/sbin/sshd /usr/local/sbin/sshd /usr/bin/sshd /sbin/sshd; do
  [ -x "$c" ] && { SSHD=$c; break; }
done
[ -z "$SSHD" ] && SSHD=$(command -v sshd 2>/dev/null)
if [ -z "$SSHD" ]; then echo sshd=no; exit 0; fi
echo sshd=yes

ver=$({ "$SSHD" -V 2>&1; "$SSHD" -h 2>&1; } | grep -o 'OpenSSH_[0-9][0-9.]*p[0-9]*' | head -n1 | sed 's/OpenSSH_//')
echo "ver=$ver"

if [ -r /lib/apk/db/installed ]; then
  awk '/^P:/{p=substr($0,3)} /^V:/{v=substr($0,3)} /^t:/{t=substr($0,3)}
       /^$/{ if (p ~ /^openssh-server/) print "pkg=" p "|" v "|" t; p=""; v=""; t="" }
       END{ if (p ~ /^openssh-server/) print "pkg=" p "|" v "|" t }' /lib/apk/db/installed
  # Compare against the first fixed package of this Alpine branch (handles backports)
  if [ -n "$AREL" ] && command -v apk >/dev/null 2>&1; then
    case "$AREL" in *_*) br=edge ;; *) br=$(echo "$AREL" | cut -d. -f1,2) ;; esac
    fx=$(printf '%s\n' $FIXED_TABLE | sed -n "s/^$br=//p")
    pv=$(awk '/^P:/{p=substr($0,3)} /^V:/{ if (p ~ /^openssh-server/) { print substr($0,3); exit } }' /lib/apk/db/installed)
    echo "branch=$br"
    if [ -n "$fx" ] && [ -n "$pv" ]; then
      r=$(apk version -t "$pv" "$fx" 2>/dev/null | head -n1)
      case "$r" in '<'|'='|'>') echo "apkcmp=$r"; echo "fixed_pkg=$fx" ;; esac
    fi
  fi
fi

pl=no
for b in "$SSHD" /usr/lib/ssh/sshd-session /usr/libexec/sshd-session /usr/lib/openssh/sshd-session; do
  [ -f "$b" ] && grep -q libpam "$b" 2>/dev/null && pl=yes
done
echo "pam_linked=$pl"

# Effective config. `sshd -T` needs a host key; images usually have none yet,
# so retry with a throwaway key in a temp dir.
EFF=$("$SSHD" -T 2>/dev/null)
if [ -z "$EFF" ] && command -v ssh-keygen >/dev/null 2>&1; then
  TD=$(mktemp -d 2>/dev/null)
  if [ -n "$TD" ] && ssh-keygen -q -t ed25519 -N '' -f "$TD/k" >/dev/null 2>&1; then
    EFF=$("$SSHD" -T -h "$TD/k" 2>/dev/null)
  fi
  [ -n "$TD" ] && rm -rf "$TD"
fi
if [ -n "$EFF" ]; then
  echo cfg_src=sshd-T
  printf '%s\n' "$EFF" | awk '$1=="passwordauthentication"{print "pa="$2}
                              $1=="usepam"{print "usepam="$2}
                              $1=="port"{print "port="$2}
                              $1=="permitrootlogin"{print "prl="$2}'
else
  echo cfg_src=parse
  CF=/etc/ssh/sshd_config
  [ -d /etc/ssh/sshd_config.d ] && CF="$(ls /etc/ssh/sshd_config.d/*.conf 2>/dev/null) $CF"
  cat $CF 2>/dev/null | awk '
    /^[ \t]*#/ {next}
    { k=tolower($1) }
    k=="match" {exit}
    k=="passwordauthentication" && pa=="" {pa=tolower($2)}
    k=="usepam" && up=="" {up=tolower($2)}
    k=="port" && pt=="" {pt=$2}
    k=="permitrootlogin" && prl=="" {prl=tolower($2)}
    END{ print "pa=" (pa==""?"yes":pa); print "usepam=" (up==""?"no":up);
         print "port=" (pt==""?"22":pt); print "prl=" (prl==""?"prohibit-password":prl) }'
fi

if [ -r /etc/shadow ]; then
  echo "star=$(awk -F: '$2=="*"{printf "%s ",$1}' /etc/shadow)"
  echo "hashed=$(awk -F: '$2 ~ /^[$][56][$]/{printf "%s ",$1}' /etc/shadow)"
else
  echo shadow=unreadable
fi

run=no; mpid=""
for p in /proc/[0-9]*; do
  [ "$(cat "$p/comm" 2>/dev/null)" = sshd ] || continue
  run=yes
  pp=$(awk '{print $4}' "$p/stat" 2>/dev/null)
  [ "$(cat "/proc/$pp/comm" 2>/dev/null)" = sshd ] && continue
  [ -z "$mpid" ] && mpid=${p#/proc/}
done
[ -z "$mpid" ] && for f in /run/sshd.pid /var/run/sshd.pid; do [ -r "$f" ] && mpid=$(cat "$f") && break; done
echo "running=$run"
echo "mpid=$mpid"

for f in /var/log/messages /var/log/auth.log /var/log/secure; do
  [ -r "$f" ] && grep -h "Accepted password for" "$f" 2>/dev/null
done | sed -n 's/.*Accepted password for \([^ ]*\) from.*/acc=\1/p' | sort -u

if [ "${SSHOLE_ONLINE:-0}" = 1 ] && command -v apk >/dev/null 2>&1; then
  if apk update -q >/dev/null 2>&1; then
    if apk version -l '<' 2>/dev/null | grep -q '^openssh'; then echo online=outdated; else echo online=uptodate; fi
  else
    echo online=failed
  fi
fi
EOF
)
PROBE="FIXED_TABLE='$FIXED_TABLE'
$PROBE_BODY"

# Interim mitigation: PasswordAuthentication no, prepended to sshd_config
# (sshd uses the first value it sees, so this beats Include'd drop-ins too)
MITIGATE_SH=$(cat <<'EOF'
set -e
F=/etc/ssh/sshd_config
[ -f "$F" ] || { echo "  $F not found"; exit 1; }
if ! head -n1 "$F" | grep -q 'CVE-2026-123158'; then
  cp "$F" "$F.sshole.bak"
  { echo "PasswordAuthentication no # CVE-2026-123158 interim mitigation (sshole-check.sh)"; cat "$F.sshole.bak"; } > "$F"
fi
SSHD=/usr/sbin/sshd; [ -x "$SSHD" ] || SSHD=$(command -v sshd)
if ! "$SSHD" -t; then
  cat "$F.sshole.bak" > "$F"
  echo "  sshd -t failed, change reverted"; exit 1
fi
[ -n "${MPID:-}" ] && kill -HUP "$MPID"
echo "  effective setting: $("$SSHD" -T 2>/dev/null | grep -i '^passwordauthentication' || echo '?')"
if grep -qiE '^[[:space:]]*Match' "$F" /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
   && grep -qiE '^[[:space:]]+PasswordAuthentication[[:space:]]+yes' "$F" /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
  echo "  WARNING: a Match block contains 'PasswordAuthentication yes', check it manually."
fi
EOF
)

# Interim mitigation: upgrade openssh packages, make sshd re-exec itself via SIGHUP
UPGRADE_SH=$(cat <<'EOF'
set -e
command -v apk >/dev/null 2>&1 || { echo "  no apk, skipped"; exit 1; }
L=$(apk info 2>/dev/null | grep '^openssh' | tr '\n' ' ')
apk update -q
apk add -u -q $L
SSHD=/usr/sbin/sshd; [ -x "$SSHD" ] || SSHD=$(command -v sshd)
"$SSHD" -t
[ -n "${MPID:-}" ] && kill -HUP "$MPID"
echo "  installed: $(apk info -v 2>/dev/null | grep '^openssh-server' | tr '\n' ' ')"
EOF
)

# ---------------------------------------------------------------------------
get(){    printf '%s\n' "$2" | sed -n "s/^$1=//p" | head -n1; }
getall(){ printf '%s\n' "$2" | sed -n "s/^$1=//p"; }
fmt_date(){ date -u -d "@$1" +%F 2>/dev/null || date -u -r "$1" +%F 2>/dev/null || echo "$1"; }
trim(){ printf '%s' "$1" | sed 's/^ *//; s/ *$//'; }

# OpenSSH version compare ("9.9p2" vs "10.6p2") without relying on `sort -V`
ver_num(){
  local v="$1" maj min p=0
  case "$v" in *p*) p=${v##*p}; v=${v%p*} ;; esac
  maj=${v%%.*}; min=${v#*.}; [ "$min" = "$v" ] && min=0; min=${min%%.*}
  printf '%d' $(( 10#${maj:-0} * 10000 + 10#${min:-0} * 100 + 10#${p:-0} )) 2>/dev/null || echo 0
}
ver_ge(){ [ "$(ver_num "$1")" -ge "$(ver_num "$2")" ]; }

confirm(){
  [ "$YES" -eq 1 ] && return 0
  local a; read -r -p "$1 [y/N] " a </dev/tty || return 1
  [[ "$a" =~ ^[yY] ]]
}

report(){
  local v="$1" kind="$2" name="$3" label="$4" c; shift 4
  case "$v" in
    OK)     c=$G; N_OK=$((N_OK+1)) ;;
    WARN)   c=$Y; N_WARN=$((N_WARN+1)) ;;
    VULN)   c=$R; N_VULN=$((N_VULN+1)) ;;
    BREACH) c=$M; N_ALERT=$((N_ALERT+1)) ;;
    *)      c=$D; N_SKIP=$((N_SKIP+1)) ;;
  esac
  if [ "$QUIET" -eq 1 ] && { [ "$v" = OK ] || [ "$v" = SKIP ]; }; then return; fi
  printf '%s[%-6s]%s %-9s %s%s%s %s%s%s\n' "$c" "$v" "$N" "$kind" "$B" "$name" "$N" "$D" "$label" "$N"
  local l; for l in "$@"; do [ -n "$l" ] && printf '                   %s\n' "$l"; done
}

analyze(){
  local kind="$1" name="$2" label="$3" out="$4" pub="$5" logacc="$6"
  local sshd musl os arel ver pa usepam paml prl ports star hashed run online shadow apkcmp fxpkg branch
  local tmax=0 pkgs="" fixed fixsrc pam_on=no star_eff="" sus="" verdict p v t u a
  local -a why=() notes=()

  sshd=$(get sshd "$out")
  if [ "$sshd" != yes ]; then report OK "$kind" "$name" "$label" "no sshd"; return; fi

  musl=$(get musl "$out"); os=$(get os "$out"); arel=$(get alpine_release "$out")
  ver=$(get ver "$out"); pa=$(get pa "$out"); usepam=$(get usepam "$out")
  paml=$(get pam_linked "$out"); prl=$(get prl "$out"); online=$(get online "$out")
  apkcmp=$(get apkcmp "$out"); fxpkg=$(get fixed_pkg "$out"); branch=$(get branch "$out")
  ports=$(trim "$(getall port "$out" | tr '\n' ' ')")
  star=$(trim "$(get star "$out")"); hashed=$(trim "$(get hashed "$out")")
  shadow=$(get shadow "$out"); run=$(get running "$out")

  while IFS='|' read -r p v t; do
    [ -z "$p" ] && continue
    pkgs+="$p-$v "
    [ -n "$t" ] && [ "$t" -gt "$tmax" ] 2>/dev/null && tmax=$t
  done < <(getall pkg "$out")
  pkgs=$(trim "$pkgs")

  if [ "$musl" != yes ]; then
    report OK "$kind" "$name" "$label" "OpenSSH ${ver:-?} · $os · not musl (glibc), out of scope"
    return
  fi

  # Patch status: upstream version > Alpine branch table (backports) > build date heuristic
  if [ -n "$ver" ] && ver_ge "$ver" "$FIX_VER"; then
    fixed=yes; fixsrc="version ≥ $FIX_VER"
  elif [ -n "$apkcmp" ]; then
    if [ "$apkcmp" = '<' ]; then fixed=no; fixsrc="package older than $fxpkg, the Alpine $branch fix"
    else fixed=yes; fixsrc="package ≥ $fxpkg, Alpine $branch backport"; fi
  elif [ "$tmax" -gt 0 ]; then
    if [ "$tmax" -ge "$FIX_EPOCH" ]; then fixed=yes; else fixed=no; fi
    fixsrc="package build date $(fmt_date "$tmax"), heuristic"
  elif [ -n "$ver" ]; then
    fixed=no; fixsrc="version $ver < $FIX_VER"
  else
    fixed=unknown; fixsrc="could not read version"
  fi
  case "$online" in
    outdated) fixed=no; fixsrc="$fixsrc; apk has a newer openssh" ;;
    uptodate) [ "$fixed" = unknown ] && { fixed=yes; fixsrc="apk: latest package installed"; } ;;
    failed)   notes+=("--online: apk update failed (no network?)") ;;
  esac

  [ "$paml" = yes ] && [ "$usepam" = yes ] && pam_on=yes

  for u in $star; do
    if [ "$u" = root ] && [ "$prl" != yes ]; then
      notes+=("root is '*' but PermitRootLogin=$prl, root cannot log in with a password")
      continue
    fi
    star_eff+="$u "
  done
  star_eff=$(trim "$star_eff")

  if [ "$fixed" = yes ]; then
    verdict=OK; why+=("patched ($fixsrc)")
  elif [ "$pam_on" = yes ]; then
    verdict=OK; why+=("PAM in use (UsePAM yes), not affected; update anyway")
  elif [ "$pa" = no ]; then
    verdict=WARN; why+=("unpatched ($fixsrc) but PasswordAuthentication no")
  elif [ "$shadow" = unreadable ]; then
    verdict=WARN; why+=("unpatched ($fixsrc), /etc/shadow unreadable (run as root)")
  elif [ -n "$star_eff" ] && [ -n "$hashed" ]; then
    verdict=VULN; why+=("unpatched ($fixsrc) and all conditions are met")
  else
    verdict=WARN; why+=("unpatched ($fixsrc); conditions not met right now, becomes exploitable once an account gets a password")
  fi

  for a in $logacc; do
    case " $star " in *" $a "*) sus+="$a " ;; esac
  done
  if [ -n "$sus" ]; then
    verdict=BREACH
    why+=("'Accepted password' logged for passwordless account(s): $(trim "$sus")")
  fi

  [ "$verdict" = VULN ] && [ "$kind" = image ] && notes+=("every container started from this image with sshd will be vulnerable")
  [ "$verdict" = VULN ] && [ "$run" = yes ] && [ -n "$pub" ] && notes+=("${R}sshd is running and published to the outside${N}")

  local d4
  if [ "$kind" = image ]; then d4="${pub:-no EXPOSE}"
  else d4="sshd running: ${run:-?}${pub:+ · published: $pub}"; fi

  report "$verdict" "$kind" "$name" "$label" \
    "OpenSSH ${ver:-?} · ${pkgs:-no apk package} · ${os}${arel:+ $arel}" \
    "PasswordAuthentication=${pa:-?} · PAM=$([ "$pam_on" = yes ] && echo on || echo off) · PermitRootLogin=${prl:-?} · port: ${ports:-?}" \
    "'*' accounts: ${star:--} · \$5\$/\$6\$ hashed: ${hashed:--}" \
    "$d4" \
    "${why[@]/#/→ }" \
    ${notes[@]+"${notes[@]/#/· }"}

  if [ "$kind" = container ] && [ "$run" = yes ] && [ "$fixed" != yes ] && [ "$pam_on" != yes ]; then
    RISKY+=("$CUR_ID|$name|$CUR_MPID|$pa|$fixed")
  fi
}

# ---------------------------------------------------------------------------
scan_host(){
  if [ ! -e /etc/alpine-release ] && ! ls /lib/ld-musl-* >/dev/null 2>&1; then
    report SKIP host "${HOSTNAME:-host}" "" "not musl-based"
    return
  fi
  local out; out=$(sh -s <<<"$PROBE" 2>/dev/null)
  [ "$(id -u)" -ne 0 ] && echo "${Y}note:${N} without root the host check cannot read /etc/shadow, run with sudo." >&2
  CUR_ID=""; CUR_MPID=""
  analyze host "${HOSTNAME:-host}" "(host)" "$out" "" "$(getall acc "$out" | tr '\n' ' ')"
}

scan_containers(){
  local id name img net out pub accs p m
  for id in $($DOCKER ps -q); do
    name=$($DOCKER inspect -f '{{.Name}}' "$id" 2>/dev/null | sed 's#^/##')
    img=$($DOCKER inspect -f '{{.Config.Image}}' "$id" 2>/dev/null)
    net=$($DOCKER inspect -f '{{.HostConfig.NetworkMode}}' "$id" 2>/dev/null)
    out=$($TMO $DOCKER exec -i -u 0 -e SSHOLE_ONLINE="$DO_ONLINE" "$id" sh -s <<<"$PROBE" 2>/dev/null)
    if [ -z "$out" ]; then report SKIP container "$name" "$img" "no shell or exec failed"; continue; fi

    pub=""; accs=""
    if [ "$(get sshd "$out")" = yes ]; then
      if [ "$net" = host ]; then
        pub="host network (port $(trim "$(getall port "$out" | tr '\n' ' ')"))"
      else
        for p in $(getall port "$out"); do
          m=$($DOCKER port "$id" "$p/tcp" 2>/dev/null | tr '\n' ' ')
          [ -n "$m" ] && pub+="$p→$(trim "$m") "
        done
        pub=$(trim "$pub")
      fi
      accs=$(getall acc "$out")
      if [ "$DO_LOGS" -eq 1 ]; then
        accs+=$'\n'$($DOCKER logs "$id" 2>&1 | sed -n 's/.*Accepted password for \([^ ]*\) from.*/\1/p')
      fi
      accs=$(printf '%s\n' "$accs" | sed '/^$/d' | sort -u | tr '\n' ' ')
    fi
    CUR_ID=$id; CUR_MPID=$(get mpid "$out")
    analyze container "$name" "$img" "$out" "$pub" "$accs"
  done
}

scan_images(){
  local id ref out exposed
  while read -r id ref; do
    [ -z "$id" ] && continue
    [ "$ref" = "<none>:<none>" ] && ref=$id
    out=$($TMO $DOCKER run --rm -i --network none --entrypoint sh -u 0 "$id" -s <<<"$PROBE" 2>/dev/null)
    if [ -z "$out" ]; then report SKIP image "$ref" "" "no shell (distroless/scratch)"; continue; fi
    exposed=$($DOCKER image inspect -f '{{range $p, $v := .Config.ExposedPorts}}{{$p}} {{end}}' "$id" 2>/dev/null)
    exposed=$(trim "$exposed")
    CUR_ID=""; CUR_MPID=""
    analyze image "$ref" "$id" "$out" "${exposed:+EXPOSE $exposed}" ""
  done < <($DOCKER image ls --format '{{.ID}} {{.Repository}}:{{.Tag}}' | awk '!s[$1]++')
}

act(){
  echo
  if [ ${#RISKY[@]} -eq 0 ]; then echo "No running container needs an interim mitigation."; return; fi
  local r id name mpid pa fixed
  for r in "${RISKY[@]}"; do
    IFS='|' read -r id name mpid pa fixed <<<"$r"
    if [ "$DO_UPGRADE" -eq 1 ] && confirm "${B}$name${N}: upgrade openssh packages and reload sshd?"; then
      echo "→ $name: upgrading"
      $DOCKER exec -i -u 0 -e MPID="$mpid" "$id" sh -s <<<"$UPGRADE_SH" || echo "  ${R}failed${N}"
    fi
    if [ "$DO_MITIGATE" -eq 1 ] && [ "$pa" != no ] \
       && confirm "${B}$name${N}: set PasswordAuthentication no and reload sshd?"; then
      echo "→ $name: disabling password login"
      $DOCKER exec -i -u 0 -e MPID="$mpid" "$id" sh -s <<<"$MITIGATE_SH" || echo "  ${R}failed${N}"
    fi
  done
  echo "${Y}These changes are temporary: they are lost when the container is recreated. Rebuild your images.${N}"
}

# ---------------------------------------------------------------------------
echo "${B}CVE-2026-123158 (*SSHole) audit${N} ${D}· sshole-check $VERSION · $(date -u '+%F %T') UTC${N}"
echo

if [ "$DO_CONTAINERS" -eq 1 ] || [ "$DO_IMAGES" -eq 1 ]; then
  if ! command -v "$DOCKER" >/dev/null 2>&1 || ! $DOCKER info >/dev/null 2>&1; then
    echo "${Y}warning:${N} '$DOCKER' is not reachable (not installed or no permission). Skipping container/image scan." >&2
    DO_CONTAINERS=0; DO_IMAGES=0
  fi
fi

[ "$DO_HOST" -eq 1 ]       && scan_host
[ "$DO_CONTAINERS" -eq 1 ] && scan_containers
[ "$DO_IMAGES" -eq 1 ]     && scan_images

if [ "$DO_MITIGATE" -eq 1 ] || [ "$DO_UPGRADE" -eq 1 ]; then act; fi

echo
echo "${B}Summary:${N} ${G}OK=$N_OK${N} ${Y}WARN=$N_WARN${N} ${R}VULN=$N_VULN${N} ${M}BREACH=$N_ALERT${N} ${D}SKIPPED=$N_SKIP${N}"

if [ $((N_VULN + N_WARN + N_ALERT)) -gt 0 ]; then
  cat <<EOF

${B}Permanent fix${N}
  Dockerfile:   FROM alpine:<3.21.10 | 3.22.8 | 3.23.8 | 3.24.4 or later>
                RUN apk upgrade --no-cache
  Build:        docker build --pull --no-cache -t <image> .
  Recreate:     docker compose up -d --force-recreate
  Hardening:    PasswordAuthentication no in sshd_config · don't publish the SSH port to the internet
EOF
  [ "$N_ALERT" -gt 0 ] && echo "  ${M}Isolate and investigate BREACH targets: a successful password login for a passwordless account was found.${N}"
fi

if   [ $((N_VULN + N_ALERT)) -gt 0 ]; then exit 2
elif [ "$N_WARN" -gt 0 ]; then exit 1
else exit 0; fi
