# Deepsleuth — deterministic MCP security scanner.
# Static/manifest scanning runs fully inside this image. The dynamic layer
# launches target servers in Docker, so mount the host Docker socket to enable it:
#   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
#     -v "$PWD:/targets" deepsleuth scan /targets/<server-dir>
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Deepsleuth" \
      org.opencontainers.image.description="Deterministic deep-visibility security scanner for MCP servers (no LLM)." \
      org.opencontainers.image.licenses="Apache-2.0"

# The scanner itself has zero third-party runtime deps — nothing to apt-install.
COPY . /opt/deepsleuth
WORKDIR /opt/deepsleuth
RUN pip install --no-cache-dir .

# Non-root: the scanner only needs read access to targets plus its pins dir.
RUN useradd --system --create-home scanner && chown -R scanner:scanner /opt/deepsleuth
USER scanner

ENTRYPOINT ["deepsleuth"]
CMD ["--help"]