FROM rust:1.98.0-alpine3.24@sha256:a10e64dd139b7387337c7fbe8aca31b959b57b2fd4c8ae20a02cf1d6ea424dce AS builder

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'pub fn placeholder() {}' > src/lib.rs \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --locked --release \
    && rm -rf src

COPY src/ src/
ARG LUX_BUILD_SHA=unknown
ENV LUX_BUILD_SHA=${LUX_BUILD_SHA}
RUN touch src/lib.rs src/main.rs \
    && cargo build --locked --release --bin lux --bin lux-healthcheck \
    && mkdir -p /runtime/data \
    && chmod 0700 /runtime/data

FROM scratch

ARG LUX_BUILD_SHA=unknown
ARG LUX_VERSION=development
LABEL org.opencontainers.image.title="Lux" \
      org.opencontainers.image.description="Lux application database engine" \
      org.opencontainers.image.source="https://github.com/lux-db/lux" \
      org.opencontainers.image.revision="${LUX_BUILD_SHA}" \
      org.opencontainers.image.version="${LUX_VERSION}" \
      org.opencontainers.image.licenses="MIT"

ENV LUX_BIND_HOST=0.0.0.0 \
    LUX_DATA_DIR=/data \
    LUX_HTTP_PORT=5890

COPY --from=builder /build/target/release/lux /lux
COPY --from=builder /build/target/release/lux-healthcheck /lux-healthcheck
COPY --from=builder --chown=10001:10001 /runtime/data/ /data/

USER 10001:10001

EXPOSE 6379 5890
VOLUME ["/data"]
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 CMD ["/lux-healthcheck", "ready"]

ENTRYPOINT ["/lux"]
