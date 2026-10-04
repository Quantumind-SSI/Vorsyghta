#!/usr/bin/env bash
set -euo pipefail
LOG=./scripts/installed_deps.txt
: > "$LOG"

echo "Checking and installing dependencies..." >&2
# Commands to verify (these represent components in the flow)
cmds=(git curl docker qemu-system-x86_64 virsh gh python3 pip3)

# Mapping from command -> package name per package manager (primary: apt)
declare -A pkg_map
pkg_map[git]=git
pkg_map[curl]=curl
pkg_map[docker]=docker.io
pkg_map[qemu-system-x86_64]=qemu-kvm
pkg_map[virsh]=libvirt-clients
pkg_map[gh]=gh
pkg_map[python3]=python3
pkg_map[pip3]=python3-pip

# Detect package manager
PM="none"
if command -v apt-get >/dev/null 2>&1; then PM=apt
elif command -v dnf >/dev/null 2>&1; then PM=dnf
elif command -v yum >/dev/null 2>&1; then PM=yum
elif command -v pacman >/dev/null 2>&1; then PM=pacman
fi

echo "Detected package manager: $PM" >&2

missing=()
for c in "${cmds[@]}"; do
  if command -v "$c" >/dev/null 2>&1; then
    echo "$c: present" | tee -a "$LOG"
  else
    echo "$c: missing" | tee -a "$LOG"
    missing+=("$c")
  fi
done

if [ "${#missing[@]}" -eq 0 ]; then
  echo "All dependencies present." >&2
  exit 0
fi

if [ "$PM" = "none" ]; then
  echo "No supported package manager found. Missing: ${missing[*]}" >&2
  exit 2
fi

# Build install list using mapping when available
install_pkgs=()
for c in "${missing[@]}"; do
  pkg_name="${pkg_map[$c]:-$c}"
  install_pkgs+=("$pkg_name")
done

# Attempt install (may require sudo)
case "$PM" in
  apt)
    echo "Running: sudo apt-get update && sudo apt-get install -y ${install_pkgs[*]}" >&2
    sudo apt-get update -y && sudo apt-get install -y "${install_pkgs[@]}" || true
    ;;
  dnf)
    sudo dnf install -y "${install_pkgs[@]}" || true
    ;;
  yum)
    sudo yum install -y "${install_pkgs[@]}" || true
    ;;
  pacman)
    sudo pacman -Sy --noconfirm "${install_pkgs[@]}" || true
    ;;
esac

# Re-check and report
still_missing=()
for c in "${missing[@]}"; do
  if command -v "$c" >/dev/null 2>&1; then
    echo "$c: installed" | tee -a "$LOG"
  else
    echo "$c: still missing" | tee -a "$LOG"
    still_missing+=("$c")
  fi
done

if [ "${#still_missing[@]}" -ne 0 ]; then
  echo "ERROR: Failed to install: ${still_missing[*]}. See $LOG" >&2
  exit 3
fi

echo "All required commands are present or were installed. See $LOG" >&2
exit 0
