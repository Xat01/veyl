# Veyl API image.
#
# NOTE: this image has never been built. Docker is not available in the
# environment this project was developed in, so treat the first `docker build`
# as the real test. See docs/DEPLOYMENT.md.
#
# The scanner is a TCP connect scanner, which needs no raw sockets and no
# CAP_NET_RAW. That is why this image runs as an unprivileged user rather than
# asking for capabilities: the scanning the product does by default does not
# require them.

FROM python:3.13-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Build deps are installed in a builder stage so the compiler toolchain does not
# end up in the runtime image.
FROM base AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY apps/ ./apps/
COPY packages/ ./packages/
COPY services/ ./services/

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip && pip install ".[postgres]"


FROM base AS runtime

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# The demo target ships with the repo and is used by `python -m veyl_api.demo`.
# It is a fixture, not part of the product, but it is small and it makes the
# image self-demonstrating.
COPY demo/ ./demo/
COPY docs/ ./docs/

# Run unprivileged. A container that holds the exposure map should not also be
# able to write to its own code.
RUN useradd --create-home --uid 10001 veyl \
 && mkdir -p /app/artifacts \
 && chown -R veyl:veyl /app
USER veyl

# Defaults that are safe to bake in. Everything security-relevant comes from the
# environment at runtime; in particular VEYL_SECRET_KEY is deliberately NOT set
# here, so the settings model's production guard fires rather than a container
# starting with a key nobody chose.
ENV VEYL_ENV=production \
    VEYL_DATABASE_URL=sqlite:////app/data/veyl.db \
    VEYL_ARTIFACT_DIR=/app/artifacts

EXPOSE 8000

# Binding 0.0.0.0 inside a container is correct: the container's network
# namespace is the boundary, not the bind address. On a host, the default bind
# is loopback.
CMD ["python", "-m", "veyl_api", "--host", "0.0.0.0", "--port", "8000"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"
