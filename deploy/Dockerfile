# syntax=docker/dockerfile:1
#
# gateclerk site agent — the Alpine/musl container install (one container per site).
#
# This is the alternative to deploy/gateclerk-agent@.service, not a replacement: the
# command line, the state layout and the credential rules are the same. The unit's
# per-site split becomes one compose service and one named volume per site.
#
# Build from the REPOSITORY ROOT (the wheel needs pyproject.toml, README.md and src/):
#   docker build -f deploy/Dockerfile -t gateclerk-agent:local .
#
# What is deliberately true of this image:
#   * non-root: uid/gid 10001, no shell login, state dir owned by it;
#   * no secret baked in: credentials arrive at run time through the resolver's existing
#     env rung (config.env_var_names) or a mounted credentials dir; the image disables
#     the file-store rung so a stray ~/.config file cannot silently answer;
#   * state on a volume: --state-root is the compose service's named volume, because the
#     sqlite store, park/ and health/ all live under it (agent_cli.resolve_state_root);
#   * TZ=Europe/Bucharest plus the tzdata package, matching the site iana_tz; the
#     sites.toml iana_tz remains payroll truth, TZ only fixes the process locale;
#   * musl: every runtime dependency in pyproject.toml is pure Python today, so the
#     builder stage needs no gcc/musl-dev. If a future dependency grows a C extension,
#     add the compiler to the `build` stage only — never to `runtime`.

FROM python:3.12-alpine AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

# Only the wheel inputs; the test suite, docs and .git are not sent into the image.
COPY pyproject.toml README.md ./
COPY src ./src

# A virtualenv is the image's install root. It is built as root in this disposable
# stage; the runtime stage copies it and never runs pip.
RUN python -m venv /opt/gateclerk \
    && /opt/gateclerk/bin/pip install --no-cache-dir .

FROM python:3.12-alpine AS runtime

# tzdata is what makes ZoneInfo("Europe/Bucharest") work on musl; Alpine ships no
# tz database by default. The agent computes device-local windows from the site zone.
RUN apk add --no-cache tzdata \
    && addgroup -S -g 10001 gateclerk \
    && adduser -S -D -H -u 10001 -G gateclerk -h /var/lib/gateclerk/site-a gateclerk \
    && install -d -o gateclerk -g gateclerk -m 0750 /var/lib/gateclerk/site-a

COPY --from=build /opt/gateclerk /opt/gateclerk
COPY --chmod=0755 deploy/container_healthcheck.sh /usr/local/bin/gateclerk-healthcheck

ENV PATH="/opt/gateclerk/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Europe/Bucharest \
    HOME=/var/lib/gateclerk/site-a \
    GATECLERK_CREDENTIALS_FILE=off \
    GATECLERK_HEALTH_FILE=/var/lib/gateclerk/site-a/health/agent.json

WORKDIR /var/lib/gateclerk/site-a
USER 10001:10001

# The snapshot is written by `agent run` to <state dir>/health/agent.json
# (agent_cli.HEALTH_DIR_NAME / HEALTH_FILE_NAME). This check reads its AGE from the
# state volume, not process liveness; 900 s is three default 300 s polls.
HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=3 \
    CMD ["/usr/local/bin/gateclerk-healthcheck"]

# The exact `agent run` surface from agent_cmds.agent_run (agent_cli resolves the
# state dir and writes <state-root>/health/agent.json). Compose overrides --site and
# --state-root per service; the default is the documented single-site example.
ENTRYPOINT ["gateclerk"]
CMD ["agent", "run", "--site", "site-a", "--config", "/etc/gateclerk/sites.toml", "--state-root", "/var/lib/gateclerk/site-a"]
