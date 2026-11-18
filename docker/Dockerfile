# QIRA (Python 3 port + QEMU plugin tracer) on Debian 13 (default) or Ubuntu 26.04.
#
#   docker/build.sh                      # both images: qira:debian13, qira:ubuntu26.04
#   docker build -f docker/Dockerfile --build-arg BASE=ubuntu:26.04 -t qira:ubuntu26.04 .
#   docker run --rm -p 3002:3002 qira:debian13            # traces /opt/qira/examples/loop
#   docker run --rm -p 3002:3002 -v "$PWD:/work" qira:debian13 /work/<binary>
#
# Stages: qemu-build (upstream QEMU with TCG plugins + libqira.so), app-build (the uv
# project in a venv), test (runs the test suite, `--target test`), runtime (default).
# The legacy reference image (qira-legacy, Ubuntu 16.04) is built from commit 862c3aa,
# not from this file (UPGRADE.md, "Legacy reference").

ARG BASE=debian:13
# QEMU release the plugin is built against (docs/tracer-assessment.md: pin 11.1.x)
ARG QEMU_TAG=v11.1.3
# linux-user targets to build; the plugin tracer supports x86_64 so far (Stage 1A adds more)
ARG QEMU_TARGETS=x86_64-linux-user
ARG UV_VERSION=0.13

FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

# ---- upstream QEMU with plugins, and the QIRA plugin ---------------------------------
FROM ${BASE} AS qemu-build
ARG QEMU_TAG
ARG QEMU_TARGETS
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential ca-certificates git meson ninja-build pkg-config libglib2.0-dev \
      python3 python3-venv flex bison \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${QEMU_TAG}" https://github.com/qemu/qemu.git /src/qemu
WORKDIR /src/qemu/build
RUN ../configure --prefix=/opt/qemu --target-list="${QEMU_TARGETS}" --enable-plugins \
      --disable-tools --disable-docs --disable-rust --disable-werror \
 && make -j"$(nproc)" \
 && make install
COPY tracers/qemu-plugin /src/qemu-plugin
RUN make -C /src/qemu-plugin libqira.so QEMU_PLUGIN_INCLUDE=/opt/qemu/include

# ---- the Python package in /opt/qira/venv --------------------------------------------
FROM ${BASE} AS app-build
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential ca-certificates python3 python3-dev \
 && rm -rf /var/lib/apt/lists/*
COPY --from=uv /uv /usr/local/bin/uv
# the distribution's Python, never a downloaded one; the venv is copied into runtime as is
ENV UV_PYTHON=/usr/bin/python3 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/qira/venv \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1
WORKDIR /src/qira
COPY . .
RUN uv sync --frozen --no-dev --no-editable

# ---- test suite: docker build --target test ------------------------------------------
FROM app-build AS test
COPY --from=qemu-build /opt/qemu/bin/ /opt/qira/tracers/qemu/
COPY --from=qemu-build /src/qemu-plugin/libqira.so /opt/qira/tracers/qemu-plugin/libqira.so
ENV QIRA_TRACER_DIR=/opt/qira/tracers PATH=/opt/qira/tracers/qemu:$PATH
# ui tests need Firefox and are not run in the image
RUN uv sync --frozen --no-editable \
 && uv run --no-sync pytest -m "not ui"

# ---- runtime ---------------------------------------------------------------------------
FROM ${BASE} AS runtime
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 libglib2.0-0t64 libstdc++6 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --shell /bin/bash qira
COPY --from=app-build /opt/qira/venv /opt/qira/venv
COPY --from=qemu-build /opt/qemu/bin/ /opt/qira/tracers/qemu/
COPY --from=qemu-build /src/qemu-plugin/libqira.so /opt/qira/tracers/qemu-plugin/libqira.so
COPY qira_tests/bin/ /opt/qira/examples/
ENV PATH=/opt/qira/venv/bin:/opt/qira/tracers/qemu:$PATH \
    QIRA_TRACER_DIR=/opt/qira/tracers
USER qira
WORKDIR /home/qira
# web UI, socat (--server) and fork ports
EXPOSE 3002 4000 4001
ENTRYPOINT ["qira"]
CMD ["/opt/qira/examples/loop"]
