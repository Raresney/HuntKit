# HuntKit — the whole recon toolchain, baked.
#
# The external tools HuntKit drives are Linux-native (ProjectDiscovery's Go
# stack, gowitness + chromium, nmap, …), which is why a bare Windows/macOS box
# can't run them. This image carries them all, so `docker run` works anywhere
# Docker does — no apt, no `go install`, no PATH wrangling.
#
#   docker build -t huntkit .
#   docker run --rm huntkit doctor
#
# Engagement data lives in the /data volume (HUNTKIT_HOME); mount a host dir to
# keep workspaces between runs. naabu's SYN scan needs raw sockets:
#
#   docker run --rm -v "$PWD/hk-data:/data" \
#       --cap-add=NET_ADMIN --cap-add=NET_RAW \
#       huntkit recon acme.com -p acme
#
# Authorised testing only.

# --------------------------------------------------------------------------
# stage 1 — build the Go toolchain (and grab findomain's release binary)
# --------------------------------------------------------------------------
FROM golang:1.23-bookworm AS builder

# libpcap-dev: naabu links against it (cgo). unzip: findomain release asset.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV GOBIN=/go/bin
# One tool per layer would bloat the cache; a single RUN keeps the image lean
# and still fails the build loudly if any tool stops building.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest \
    && go install github.com/ffuf/ffuf/v2@latest \
    && go install github.com/hahwul/dalfox/v2@latest \
    && go install github.com/tomnomnom/assetfinder@latest \
    && go install github.com/lc/gau/v2/cmd/gau@latest \
    && go install github.com/tomnomnom/waybackurls@latest \
    && go install github.com/hakluke/hakrawler@latest \
    && go install github.com/sensepost/gowitness@latest \
    && go install github.com/owasp-amass/amass/v4/...@master

# findomain ships a prebuilt Linux binary — cheaper than compiling.
RUN curl -sSL -o /tmp/findomain.zip \
        https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip \
    && unzip -o /tmp/findomain.zip -d /go/bin \
    && chmod +x /go/bin/findomain \
    && rm /tmp/findomain.zip

# --------------------------------------------------------------------------
# stage 2 — slim runtime: chromium + the apt-native tools + HuntKit
# --------------------------------------------------------------------------
FROM debian:bookworm-slim

# nmap/whatweb: apt-native. chromium: gowitness screenshots. libpcap0.8:
# naabu's runtime dep. python3 + pip: HuntKit itself. arjun (pip) is the one
# Python-native tool in the stack.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap whatweb chromium \
        python3 python3-pip \
        libpcap0.8 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Go tools + findomain from the builder, onto PATH in one dir.
COPY --from=builder /go/bin/ /usr/local/bin/

WORKDIR /opt/huntkit
COPY . .

# PEP 668 marks the system env "externally managed"; inside a container the
# system env IS the environment, so installing into it is correct.
RUN pip install --no-cache-dir --break-system-packages -e . \
    && pip install --no-cache-dir --break-system-packages arjun

# nuclei is useless without templates; fetch them at build so first run is hot.
RUN nuclei -update-templates >/dev/null 2>&1 || true

# gowitness drives headless chromium; point it at the apt binary.
ENV HUNTKIT_HOME=/data
ENV GOWITNESS_CHROME_PATH=/usr/bin/chromium
VOLUME /data

ENTRYPOINT ["huntkit"]
CMD ["doctor"]
