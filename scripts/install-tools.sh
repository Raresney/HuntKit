#!/usr/bin/env bash
#
# install-tools.sh — install the external toolchain HuntKit drives, plus
# HuntKit itself, on a Debian-family box (Kali / Ubuntu).
#
# HuntKit degrades gracefully: any tool it can't find is simply skipped at
# runtime (`huntkit doctor` shows what's present), so a partial install still
# leaves a working framework. Run from the repo root:
#
#     bash scripts/install-tools.sh
#
# Authorised testing only — these are standard recon/scanning tools.

set -u

info() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }
note() { printf '   %s\n' "$1"; }

# --------------------------------------------------------------------------
# system packages (apt)
# --------------------------------------------------------------------------
if command -v apt >/dev/null 2>&1; then
    info "system packages (apt)"
    sudo apt update
    # golang + the tools that are cleanest from the distro, plus the build/run
    # deps for the Go tools (libpcap for naabu, chromium for gowitness).
    sudo apt install -y \
        git python3-pip python3-venv golang-go \
        nmap whatweb amass findomain libpcap-dev chromium || \
        note "some apt packages failed — continuing"
else
    note "no apt found — install git, golang, python3, nmap, whatweb yourself"
fi

# --------------------------------------------------------------------------
# Go tools -> $(go env GOPATH)/bin
# --------------------------------------------------------------------------
if command -v go >/dev/null 2>&1; then
    GOBIN_DIR="$(go env GOPATH)/bin"
    export GOBIN="$GOBIN_DIR"
    info "Go tools (-> $GOBIN_DIR)"
    go_tools=(
        github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        github.com/projectdiscovery/dnsx/cmd/dnsx@latest
        github.com/projectdiscovery/httpx/cmd/httpx@latest
        github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
        github.com/projectdiscovery/katana/cmd/katana@latest
        github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        github.com/projectdiscovery/chaos-client/cmd/chaos@latest
        github.com/ffuf/ffuf/v2@latest
        github.com/hahwul/dalfox/v2@latest
        github.com/tomnomnom/assetfinder@latest
        github.com/lc/gau/v2/cmd/gau@latest
        github.com/tomnomnom/waybackurls@latest
        github.com/hakluke/hakrawler@latest
        github.com/sensepost/gowitness@latest
    )
    for tool in "${go_tools[@]}"; do
        note "go install ${tool%@latest}"
        go install "$tool" || note "! failed: $tool (skipping)"
    done
else
    GOBIN_DIR="$HOME/go/bin"
    note "no go found — install golang first, then re-run for the Go tools"
fi

# --------------------------------------------------------------------------
# arjun (python)
# --------------------------------------------------------------------------
info "arjun (python)"
pipx install arjun 2>/dev/null ||
    pip install arjun --break-system-packages 2>/dev/null ||
    pip install --user arjun ||
    note "! arjun install failed — pip install arjun yourself"

# --------------------------------------------------------------------------
# PATH for the Go tools (Kali defaults to zsh; cover bash too)
# --------------------------------------------------------------------------
for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    [ -f "$rc" ] || continue
    grep -q 'go/bin' "$rc" || echo "export PATH=\$PATH:$GOBIN_DIR" >>"$rc"
done
export PATH="$PATH:$GOBIN_DIR"

# --------------------------------------------------------------------------
# HuntKit itself (from the repo this script lives in), in a venv
# --------------------------------------------------------------------------
here="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f "$here/pyproject.toml" ]; then
    info "HuntKit ($here)"
    python3 -m venv "$here/.venv"
    # shellcheck disable=SC1091
    . "$here/.venv/bin/activate"
    pip install -e "$here" || note "! editable install failed"
fi

# --------------------------------------------------------------------------
# nuclei templates + a final doctor
# --------------------------------------------------------------------------
if command -v nuclei >/dev/null 2>&1; then
    info "nuclei templates"
    nuclei -update-templates >/dev/null 2>&1 || note "template update skipped"
fi

info "doctor"
python3 -m huntkit doctor || true

cat <<EOF

Done. Two reminders:
  - open a new shell (or: source ~/.zshrc) so the Go tools are on PATH
  - work with the venv active:  source "$here/.venv/bin/activate"
EOF
