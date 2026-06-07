FROM python:3.12-slim

LABEL maintainer="eyadgamer1"
LABEL description="BANSHEE — Broad-Area Network Scanner for Host Enumeration and Exposure"

# Install system deps for scapy (raw sockets / pcap)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install uv for fast dependency resolution
RUN pip install --no-cache-dir uv

# Copy project files
COPY pyproject.toml .
COPY scanner/ scanner/
COPY config/ config/

# Install in editable mode
RUN uv pip install --system -e .

# Config volume so users can mount their own scope.yaml
VOLUME ["/app/config", "/app/output"]

# banshee needs NET_RAW for raw sockets (passive sniff + ICMP)
# Run with: docker run --cap-add NET_RAW --cap-add NET_ADMIN ...
ENTRYPOINT ["banshee"]
CMD ["--help"]
