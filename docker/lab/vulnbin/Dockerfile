# docker/lab/vulnbin/Dockerfile
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev socat \
    && rm -rf /var/lib/apt/lists/*

COPY vuln.c /tmp/vuln.c
COPY flag.txt /flag.txt
COPY entrypoint.sh /entrypoint.sh

# -fno-stack-protector / -no-pie keep the classic overflow exploitable for the RE/pwn workstream.
RUN gcc -fno-stack-protector -no-pie -o /opt/vuln /tmp/vuln.c \
    && rm /tmp/vuln.c \
    && chmod 0644 /flag.txt \
    && chmod +x /entrypoint.sh

EXPOSE 9001
ENTRYPOINT ["/entrypoint.sh"]
