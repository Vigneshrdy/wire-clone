# Single image, different commands per service. Zeek is deliberately NOT bundled:
# it is a large dependency only the PCAP path needs, and it is documented as a
# host dependency in docs/SETUP.md.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_SYSTEM_PYTHON=1 \
    UV_COMPILE_BYTECODE=1

WORKDIR /app

# uv from the official distroless image: no curl-pipe-to-shell install.
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv

# Dependency layer first so code edits do not reinstall the world.
COPY pyproject.toml uv.lock* /app/
RUN uv sync --no-install-project --no-dev

COPY sih_ntd /app/sih_ntd
COPY benchmarks /app/benchmarks
RUN uv sync --no-dev

# Non-root: the container reads mirrored metadata; it needs no privileges at all.
RUN useradd --create-home --uid 10001 sih && \
    mkdir -p /app/data /app/ml_artifacts && chown -R sih:sih /app
USER sih

ENV PATH="/app/.venv/bin:$PATH" \
    SIH_STORE__PATH=/app/data/sih_ntd.db \
    SIH_REGISTRY__ROOT=/app/ml_artifacts \
    SIH_API__HOST=0.0.0.0

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status==200 else 1)"

EXPOSE 8000
CMD ["sih-ntd", "api"]
