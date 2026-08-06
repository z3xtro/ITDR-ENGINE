# ── Stage 1: builder ─────────────────────────────────────────────────
# Compile deps into a wheel cache so the final image carries no build
# toolchain — smaller, fewer CVEs.
FROM python:3.12-slim AS builder

WORKDIR /build
RUN pip install --no-cache-dir --upgrade pip wheel
# httpx = async enforcement adapters; rich/textual = dashboards;
# redis = distributed state; requests = pollers.
RUN pip wheel --no-cache-dir --wheel-dir /wheels \
    rich textual httpx requests redis

# ── Stage 2: runtime ─────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Color rendering for the rich/textual dashboards inside the container.
ENV PYTHONUNBUFFERED=1 \
    FORCE_COLOR=1 \
    TERM=xterm-256color

WORKDIR /app
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

COPY itdr/ itdr/

# A containment service must never run as root.
RUN useradd --create-home itdr && chown -R itdr /app
USER itdr

HEALTHCHECK --interval=60s --timeout=5s \
  CMD python -c "import itdr" || exit 1

# Default: passive service. Override to launch the live dashboard:
#   docker compose run --rm itdr python -m itdr.tui
CMD ["python", "-m", "itdr.service"]
