# dpdpkit scanner image: `dpdpkit scan` with Excel and S3 support, as a non-root user on a read-only file system.
#   docker run --read-only --tmpfs /tmp ghcr.io/dpdpkit-dev/scanner postgresql://readonly@host/db --sample 500
#   docker run --read-only -v "$PWD/exports:/data:ro" ghcr.io/dpdpkit-dev/scanner /data --format json
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# --pre: the dpdpkit packages are alphas until 0.5 ships. psycopg and pymysql cover PostgreSQL and MySQL targets.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --pre ".[excel,s3]" "psycopg[binary]>=3.1" "pymysql>=1.1"

FROM python:3.12-slim
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
COPY --from=build /opt/venv /opt/venv
# Fixed numeric UID/GID so Kubernetes runAsNonRoot can verify it. No home directory, no writable paths.
RUN groupadd --gid 10001 dpdpkit \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin dpdpkit
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["python", "-m", "dpdpkit.pii"]
