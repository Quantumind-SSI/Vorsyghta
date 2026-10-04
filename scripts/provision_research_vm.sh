#!/usr/bin/env bash
#
# Provision Zero-Day Research Attacker VM
#
# Installs the full vulnerability discovery toolchain on an Ubuntu 24.04 VM:
#   - AFL++ (coverage-guided fuzzer)
#   - libFuzzer (LLVM in-process fuzzer)
#   - honggfuzz (hardware-based fuzzer)
#   - radamsa (mutation engine)
#   - radare2 (reverse engineering)
#   - Ghidra (decompiler / binary analysis)
#   - GDB + pwndbg (debugging / exploit dev)
#   - Semgrep (static analysis)
#   - CodeQL (semantic code analysis)
#   - Bandit (Python SAST)
#   - ffuf (web fuzzer)
#   - schemathesis (API fuzzer)
#   - nmap, nuclei, gobuster, hydra, sqlmap (offensive tools)
#   - binwalk, foremost, strings (binary utilities)
#
# Usage:
#   bash provision_research_vm.sh
#
# Or via cloud-init:
#   Pass this script as user-data when creating the VM.
#
# Environment variables:
#   GHIDRA_VERSION  - Ghidra version to install (default: 11.1.2)
#   CODEQL_VERSION  - CodeQL CLI version (default: 2.18.1)
#   RESEARCH_USER   - Username for research account (default: researcher)

set -euo pipefail

GHIDRA_VERSION="${GHIDRA_VERSION:-11.1.2}"
CODEQL_VERSION="${CODEQL_VERSION:-2.18.1}"
RESEARCH_USER="${RESEARCH_USER:-researcher}"

ok()   { echo -e "\033[32m[OK]\033[0m   $1"; }
info() { echo -e "\033[36m[INFO]\033[0m $1"; }
err()  { echo -e "\033[31m[ERR]\033[0m  $1"; }

# ---------------------------------------------------------------------------
# 1. Base packages
# ---------------------------------------------------------------------------
info "Installing base packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    build-essential gcc g++ clang clang-tools lld llvm llvm-dev \
    cmake ninja-build pkg-config autoconf automake libtool \
    git curl wget unzip tar xz-utils bzip2 \
    python3 python3-pip python3-venv python3-dev \
    gdb strace ltrace binutils elfutils \
    binwalk foremost exiftool \
    nmap nikto dirb gobuster hydra sqlmap \
    radare2 \
    netcat-openbsd socat \
    jq xmlstarlet \
    openssh-server \
    sudo less vim nano \
    2>&1 | tail -5
ok "Base packages installed"

# ---------------------------------------------------------------------------
# 2. Create research user
# ---------------------------------------------------------------------------
info "Creating research user '$RESEARCH_USER'..."
if ! id "$RESEARCH_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$RESEARCH_USER"
    echo "${RESEARCH_USER}:${RESEARCH_USER}" | chpasswd
    usermod -aG sudo "$RESEARCH_USER"
    echo "${RESEARCH_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${RESEARCH_USER}
fi
ok "Research user created"

# ---------------------------------------------------------------------------
# 3. AFL++ (coverage-guided fuzzer)
# ---------------------------------------------------------------------------
info "Installing AFL++..."
AFL_DIR="/opt/aflplusplus"
if [ ! -d "$AFL_DIR" ]; then
    git clone --depth=1 https://github.com/AFLplusplus/AFLplusplus.git "$AFL_DIR"
    cd "$AFL_DIR"
    make distrib -j$(nproc) 2>&1 | tail -3
    make install 2>&1 | tail -3
    cd /
fi
ok "AFL++ installed"

# ---------------------------------------------------------------------------
# 4. libFuzzer (part of LLVM/clang)
# ---------------------------------------------------------------------------
info "Checking libFuzzer..."
if clang --print-file-name=libclang_rt.fuzzer.a 2>/dev/null | grep -q "libclang_rt.fuzzer.a"; then
    ok "libFuzzer available via clang"
else
    info "libFuzzer not found as standalone, installing via clang..."
    apt-get install -y -qq libfuzzer-17-dev 2>/dev/null || true
    ok "libFuzzer installation attempted"
fi

# ---------------------------------------------------------------------------
# 5. honggfuzz
# ---------------------------------------------------------------------------
info "Installing honggfuzz..."
HF_DIR="/opt/honggfuzz"
if [ ! -d "$HF_DIR" ]; then
    apt-get install -y -qq libbfd-dev libunwind-dev libblocksruntime-dev 2>&1 | tail -2
    git clone --depth=1 https://github.com/google/honggfuzz.git "$HF_DIR"
    cd "$HF_DIR"
    make -j$(nproc) 2>&1 | tail -3
    make install 2>&1 | tail -3
    cd /
fi
ok "honggfuzz installed"

# ---------------------------------------------------------------------------
# 6. radamsa (mutation engine)
# ---------------------------------------------------------------------------
info "Installing radamsa..."
if ! command -v radamsa &>/dev/null; then
    apt-get install -y -qq radamsa 2>/dev/null || {
        info "Building radamsa from source..."
        git clone --depth=1 https://gitlab.com/akihe/radamsa.git /tmp/radamsa
        cd /tmp/radamsa
        make -j$(nproc) 2>&1 | tail -3
        make install 2>&1 | tail -3
        cd /
        rm -rf /tmp/radamsa
    }
fi
ok "radamsa installed"

# ---------------------------------------------------------------------------
# 7. Ghidra (decompiler / binary analysis)
# ---------------------------------------------------------------------------
info "Installing Ghidra ${GHIDRA_VERSION}..."
GHIDRA_DIR="/opt/ghidra"
GHIDRA_ZIP="/tmp/ghidra.zip"
if [ ! -d "$GHIDRA_DIR" ]; then
    apt-get install -y -qq default-jdk 2>&1 | tail -2
    wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_VERSION}_build.zip" -O "$GHIDRA_ZIP"
    unzip -q "$GHIDRA_ZIP" -d /opt/
    mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC "$GHIDRA_DIR"
    rm "$GHIDRA_ZIP"
    ln -sf "${GHIDRA_DIR}/support/analyzeHeadless" /usr/local/bin/analyzeHeadless
fi
ok "Ghidra installed at ${GHIDRA_DIR}"

# ---------------------------------------------------------------------------
# 8. GDB + pwndbg (debugging / exploit development)
# ---------------------------------------------------------------------------
info "Installing pwndbg..."
PWNDBG_DIR="/opt/pwndbg"
if [ ! -d "$PWNDBG_DIR" ]; then
    apt-get install -y -qq python3-pip python3-venv 2>&1 | tail -2
    git clone --depth=1 https://github.com/pwndbg/pwndbg.git "$PWNDBG_DIR"
    cd "$PWNDBG_DIR"
    ./setup.sh 2>&1 | tail -3
    cd /
fi
ok "pwndbg installed"

# ---------------------------------------------------------------------------
# 9. Semgrep (static analysis)
# ---------------------------------------------------------------------------
info "Installing Semgrep..."
if ! command -v semgrep &>/dev/null; then
    pip3 install semgrep 2>&1 | tail -3
fi
ok "Semgrep installed"

# ---------------------------------------------------------------------------
# 10. CodeQL (semantic code analysis)
# ---------------------------------------------------------------------------
info "Installing CodeQL CLI ${CODEQL_VERSION}..."
CODEQL_DIR="/opt/codeql"
CODEQL_ZIP="/tmp/codeql.zip"
if [ ! -d "$CODEQL_DIR" ]; then
    wget -q "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" -O "$CODEQL_ZIP"
    unzip -q "$CODEQL_ZIP" -d /opt/
    mv /opt/codeql "$CODEQL_DIR"
    rm "$CODEQL_ZIP"
    ln -sf "${CODEQL_DIR}/codeql" /usr/local/bin/codeql
fi
ok "CodeQL installed at ${CODEQL_DIR}"

# ---------------------------------------------------------------------------
# 11. Bandit (Python SAST)
# ---------------------------------------------------------------------------
info "Installing Bandit..."
pip3 install bandit 2>&1 | tail -2
ok "Bandit installed"

# ---------------------------------------------------------------------------
# 12. ffuf (web fuzzer)
# ---------------------------------------------------------------------------
info "Installing ffuf..."
if ! command -v ffuf &>/dev/null; then
    apt-get install -y -qq ffuf 2>/dev/null || {
        info "Building ffuf from source..."
        git clone --depth=1 https://github.com/ffuf/ffuf.git /tmp/ffuf
        cd /tmp/ffuf
        go build -o /usr/local/bin/ffuf 2>&1 | tail -3 || {
            # Fallback: download pre-built binary
            wget -q "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_linux_amd64.tar.gz" -O /tmp/ffuf.tar.gz
            tar xzf /tmp/ffuf.tar.gz -C /usr/local/bin/
            rm /tmp/ffuf.tar.gz
        }
        cd /
        rm -rf /tmp/ffuf
    }
fi
ok "ffuf installed"

# ---------------------------------------------------------------------------
# 13. schemathesis (API fuzzer)
# ---------------------------------------------------------------------------
info "Installing schemathesis..."
pip3 install schemathesis 2>&1 | tail -2
ok "schemathesis installed"

# ---------------------------------------------------------------------------
# 14. nuclei (vulnerability scanner)
# ---------------------------------------------------------------------------
info "Installing nuclei..."
if ! command -v nuclei &>/dev/null; then
    apt-get install -y -qq nuclei 2>/dev/null || {
        wget -q "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip" -O /tmp/nuclei.zip
        unzip -q -o /tmp/nuclei.zip -d /usr/local/bin/
        rm /tmp/nuclei.zip
    }
fi
ok "nuclei installed"

# ---------------------------------------------------------------------------
# 15. Wordlists
# ---------------------------------------------------------------------------
info "Installing wordlists..."
apt-get install -y -qq wordlists 2>/dev/null || true
if [ ! -d /usr/share/wordlists ]; then
    mkdir -p /usr/share/wordlists
    # Download common wordlists
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
        -O /usr/share/wordlists/common.txt 2>/dev/null || true
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt" \
        -O /usr/share/wordlists/big.txt 2>/dev/null || true
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt" \
        -O /usr/share/wordlists/top10000.txt 2>/dev/null || true
fi
# Create symlink for dirb wordlists if missing
if [ ! -d /usr/share/wordlists/dirb ]; then
    mkdir -p /usr/share/wordlists/dirb
    cp /usr/share/wordlists/common.txt /usr/share/wordlists/dirb/common.txt 2>/dev/null || true
fi
ok "Wordlists installed"

# ---------------------------------------------------------------------------
# 16. Setup research workspace
# ---------------------------------------------------------------------------
info "Setting up research workspace..."
WORKSPACE="/home/${RESEARCH_USER}/research"
mkdir -p "${WORKSPACE}/corpora"
mkdir -p "${WORKSPACE}/findings"
mkdir -p "${WORKSPACE}/reports"
mkdir -p "${WORKSPACE}/targets"
mkdir -p "${WORKSPACE}/scripts"

# Create a helper script for quick fuzzing
cat > "${WORKSPACE}/scripts/quick_fuzz.sh" << 'QUICKFUZZ'
#!/bin/bash
# Quick AFL++ fuzzing wrapper
# Usage: quick_fuzz.sh <target_binary> [corpus_dir] [duration_seconds]
TARGET="$1"
CORPUS="${2:-./corpora/default}"
DURATION="${3:-3600}"
OUTPUT="./findings/$(basename $TARGET)_$(date +%s)"

mkdir -p "$CORPUS" "$OUTPUT"
if [ ! -f "$CORPUS/seed" ]; then
    echo "A" > "$CORPUS/seed"
fi

echo "[*] Starting AFL++ fuzzing of $TARGET for $DURATION seconds..."
AFL_NO_AFFINITY=1 timeout "$DURATION" afl-fuzz -i "$CORPUS" -o "$OUTPUT" -- "$TARGET" @@

echo "[*] Fuzzing complete. Checking results..."
afl-whatsup -s "$OUTPUT" 2>/dev/null || true
CRASH_COUNT=$(find "$OUTPUT/default/crashes" -type f 2>/dev/null | wc -l)
echo "[*] Crashes found: $CRASH_COUNT"
echo "[*] Results in: $OUTPUT"
QUICKFUZZ
chmod +x "${WORKSPACE}/scripts/quick_fuzz.sh"

# Create crash triage helper
cat > "${WORKSPACE}/scripts/triage_crash.sh" << 'TRIAGE'
#!/bin/bash
# Triage a crash with GDB
# Usage: triage_crash.sh <target_binary> <crash_input>
TARGET="$1"
CRASH="$2"

echo "[*] Triaging crash: $CRASH against $TARGET"
echo "=========================================="
gdb -batch -q \
    -ex 'set pagination off' \
    -ex 'run < '"$CRASH" \
    -ex 'bt full' \
    -ex 'info registers' \
    -ex 'x/i $pc' \
    -ex 'x/16xw $sp' \
    -ex 'quit' \
    "$TARGET" 2>&1

echo "=========================================="
echo "[*] Crash type detection:"
GDB_OUTPUT=$(gdb -batch -q -ex 'set pagination off' -ex 'run < '"$CRASH" -ex 'quit' "$TARGET" 2>&1)
if echo "$GDB_OUTPUT" | grep -q "SIGSEGV"; then
    echo "  Type: Segmentation Fault (SIGSEGV)"
elif echo "$GDB_OUTPUT" | grep -q "SIGABRT"; then
    echo "  Type: Abort (SIGABRT)"
elif echo "$GDB_OUTPUT" | grep -q "SIGFPE"; then
    echo "  Type: Floating Point Exception (SIGFPE)"
elif echo "$GDB_OUTPUT" | grep -q "SIGBUS"; then
    echo "  Type: Bus Error (SIGBUS)"
elif echo "$GDB_OUTPUT" | grep -q "SIGILL"; then
    echo "  Type: Illegal Instruction (SIGILL)"
else
    echo "  Type: Unknown"
fi
TRIAGE
chmod +x "${WORKSPACE}/scripts/triage_crash.sh"

# Create binary analysis helper
cat > "${WORKSPACE}/scripts/analyze_binary.sh" << 'ANALYZE'
#!/bin/bash
# Quick binary analysis with radare2
# Usage: analyze_binary.sh <target_binary>
TARGET="$1"

echo "[*] Binary info:"
r2 -q -c 'iI' "$TARGET" 2>/dev/null

echo ""
echo "[*] Security mitigations:"
r2 -q -c 'iI~canary,nx,pic,relro,crypto' "$TARGET" 2>/dev/null

echo ""
echo "[*] Functions (top 20):"
r2 -q -c 'afl | head -20' "$TARGET" 2>/dev/null

echo ""
echo "[*] Strings (interesting):"
r2 -q -c 'iz~http,flag,key,pass,admin,root,secret' "$TARGET" 2>/dev/null

echo ""
echo "[*] Imports:"
r2 -q -c 'ii' "$TARGET" 2>/dev/null | head -30
ANALYZE
chmod +x "${WORKSPACE}/scripts/analyze_binary.sh"

chown -R "${RESEARCH_USER}:${RESEARCH_USER}" "${WORKSPACE}"

ok "Research workspace created at ${WORKSPACE}"

# ---------------------------------------------------------------------------
# 17. Verify installations
# ---------------------------------------------------------------------------
info "Verifying tool installations..."
TOOLS=("afl-fuzz" "honggfuzz" "radamsa" "r2" "gdb" "semgrep" "codeql" "bandit" "ffuf" "schemathesis" "nuclei" "nmap" "hydra" "sqlmap" "gobuster")
INSTALLED=0
FAILED=0
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        VERSION=$("$tool" --version 2>&1 | head -1 || echo "unknown")
        ok "  $tool: $VERSION"
        ((INSTALLED++))
    else
        err "  $tool: NOT FOUND"
        ((FAILED++))
    fi
done

# Check Ghidra separately
if [ -f "${GHIDRA_DIR}/support/analyzeHeadless" ]; then
    ok "  ghidra (analyzeHeadless): ${GHIDRA_VERSION}"
    ((INSTALLED++))
else
    err "  ghidra: NOT FOUND"
    ((FAILED++))
fi

echo ""
echo "=========================================="
echo " Installation Summary"
echo "=========================================="
echo "  Installed: $INSTALLED tools"
echo "  Failed:    $FAILED tools"
echo "  User:      $RESEARCH_USER"
echo "  Workspace: ${WORKSPACE}"
echo "=========================================="

if [ $FAILED -eq 0 ]; then
    ok "All tools installed successfully!"
else
    err "Some tools failed to install. Check logs above."
fi

info "Research VM provisioning complete."
