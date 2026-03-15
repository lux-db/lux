FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release

FROM alpine:3.20

COPY --from=builder /build/target/release/lux /usr/local/bin/lux

EXPOSE 6379

ENTRYPOINT ["lux"]
