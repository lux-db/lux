FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'pub fn placeholder() {}' > src/lib.rs \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY src/ src/
ARG LUX_BUILD_SHA=unknown
ENV LUX_BUILD_SHA=${LUX_BUILD_SHA}
RUN touch src/lib.rs src/main.rs && cargo build --release

FROM scratch

ENV LUX_BIND_HOST=0.0.0.0 \
    LUX_DATA_DIR=/data

COPY --from=builder /build/target/release/lux /lux

EXPOSE 6379
VOLUME ["/data"]

ENTRYPOINT ["/lux"]
