FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release && rm -rf src

COPY src/ src/
RUN touch src/main.rs && cargo build --release

FROM scratch

COPY --from=builder /build/target/release/lux /lux

EXPOSE 6379

ENTRYPOINT ["/lux"]
