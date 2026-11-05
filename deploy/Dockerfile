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
# The default (last) stage is `alerts`: it carries both `gateclerk` and `mnotify` in
# separate virtualenvs, because gateclerk execs mnotify as a child process and both
# must see the same filesystem (micro-notify docs/SERVICE-INTEGRATION.md, "same image").
# Build the alert-less image explicitly with:
#   docker build -f deploy/Dockerfile --target runtime -t gateclerk-agent:no-alerts .
#
# What is deliberately true of this image:
#   * non-root: uid/gid 10001, no shell login, state dirs owned by it;
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
#   * site state directories are created in the image, one per documented site. Docker
#     gives an empty named volume the ownership of its image mount point; without the
#     directory here Docker creates it as root and uid 10001 cannot write. Add a site
#     with --build-arg GATECLERK_SITES="site-a site-b site-c" (spaces).

# micro-notify is pinned to a commit SHA, not a moving branch. It is fetched as the
# GitHub archive tarball in the build stage below. Bump this one ARG deliberately.
ARG MICRO_NOTIFY_SHA=afeab1025b32feef2d856ee0350ae2fc5ee2d5f6

FROM python:3.12-alpine AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

# Only the wheel inputs; the test suite, docs and .git are not sent into the image.
COPY pyproject.toml README.md ./
COPY src ./src

# A virtualenv is the image's install root. It is built as root in this disposable
# stage; the runtime stage copies it and never runs pip.
# The `excel` extra is what makes `gateclerk users import` work in this image.
RUN python -m venv /opt/gateclerk \
    && /opt/gateclerk/bin/pip install --no-cache-dir '.[excel]'

FROM python:3.12-alpine AS mnotify-build

ARG MICRO_NOTIFY_SHA

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

# Public repo, immutable commit URL. cryptography (msal's signing dependency) ships
# musllinux wheels for this Alpine/Python pair, so this needs no Rust/gcc/musl-dev.
ADD https://github.com/pom11/micro-notify/archive/${MICRO_NOTIFY_SHA}.tar.gz /tmp/micro-notify.tar.gz

RUN mkdir -p /build/micro-notify \
    && tar -xzf /tmp/micro-notify.tar.gz -C /build/micro-notify --strip-components=1 \
    && python -m venv /opt/mnotify \
    && /opt/mnotify/bin/pip install --no-cache-dir /build/micro-notify \
    && /opt/mnotify/bin/mnotify --version

FROM python:3.12-alpine AS runtime

ARG GATECLERK_SITES="site-a site-b"

# tzdata is what makes ZoneInfo("Europe/Bucharest") work on musl; Alpine ships no
# tz database by default. The agent computes device-local windows from the site zone.
# The loop pre-creates every documented site's state dir so a named volume mounted
# there inherits uid 10001 instead of Docker's root-owned empty directory.
RUN apk add --no-cache tzdata \
    && addgroup -S -g 10001 gateclerk \
    && adduser -S -D -H -u 10001 -G gateclerk -h /var/lib/gateclerk gateclerk \
    && for site in ${GATECLERK_SITES}; do \
         install -d -o gateclerk -g gateclerk -m 0750 "/var/lib/gateclerk/${site}"; \
       done \
    && install -d -o gateclerk -g gateclerk -m 0750 \
         /var/lib/mnotify/audit \
         /var/lib/mnotify/state

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

# --- default image: gateclerk + mnotify ------------------------------------------------
#
# mnotify is a separate venv, on PATH, so gateclerk's `subprocess.run(["mnotify", ...])`
# finds the same binary an operator sees. MICRO_NOTIFY_SECRETS=file and a path-only
# SECRETS_DIR match micro-notify's Linux contract; the config and secrets are mounts,
# never image layers. [paths] (deploy/mnotify.toml.example) points audit and state at
# /var/lib/mnotify, which compose mounts as a writable named volume under read_only.
FROM runtime AS alerts

COPY --from=mnotify-build /opt/mnotify /opt/mnotify

ENV PATH="/opt/mnotify/bin:${PATH}" \
    MICRO_NOTIFY_CONFIG=/etc/mnotify/config.toml \
    MICRO_NOTIFY_SECRETS=file \
    MICRO_NOTIFY_SECRETS_DIR=/run/secrets/mnotify
