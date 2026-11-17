# Keystone ISMS container: the web app is built with Node, then served by FastAPI (uvicorn).
# Put it behind a TLS-terminating reverse proxy (see deploy/nginx/).

# ---- 1. Build the React app -------------------------------------------------------------
# Base images are pinned by digest (SC-DEP-006); update the digest together with the tag.
FROM node:22-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee AS web
WORKDIR /web
COPY web/package.json web/package-lock.json web/.npmrc ./
RUN npm ci --no-audit --no-fund   # .npmrc: ignore-scripts, exact versions (SC-DEP-003/004)
COPY web/ ./
RUN npm run build

# ---- 2. Python runtime ------------------------------------------------------------------
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    KEYSTONE_DATA_DIR=/data \
    PYTHONPATH=/app

RUN useradd --create-home --uid 10001 keystone
WORKDIR /app

COPY requirements.lock ./
RUN pip install --require-hashes -r requirements.lock   # SC-DEP-003: every package pinned and hash-checked

COPY --chown=keystone:keystone keystone/ keystone/
COPY --chown=keystone:keystone migrations/ migrations/
COPY --chown=keystone:keystone content/ content/
COPY --chown=keystone:keystone config/ config/
COPY --chown=keystone:keystone schemas/ schemas/
COPY --chown=keystone:keystone collector/ collector/
COPY --chown=keystone:keystone agents/ agents/
COPY --chown=keystone:keystone scripts/ scripts/
COPY --chown=keystone:keystone alembic.ini pyproject.toml README.md ./
COPY --from=web --chown=keystone:keystone /web/dist web/dist
# Run from the source tree (content/, config/ and web/dist are found relative to it).
RUN mkdir -p /data /backups && chown keystone:keystone /data /backups && chmod 700 /backups

USER keystone
VOLUME ["/data", "/backups"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status == 200 else 1)"

# --proxy-headers: trust X-Forwarded-For from the reverse proxy (set FORWARDED_ALLOW_IPS to its address).
CMD ["sh", "-c", "exec uvicorn keystone.api.app:create_app --factory --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-127.0.0.1}\""]
