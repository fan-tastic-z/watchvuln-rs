ARG BASE_IMAGE=rust:1.78.0-slim-buster

FROM $BASE_IMAGE as planner
WORKDIR /app
RUN cargo install cargo-chef
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM $BASE_IMAGE as cacher
WORKDIR /app
RUN cargo install cargo-chef \
    && apt update -y \
    && apt install pkg-config libssl-dev -y
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook  --release --recipe-path recipe.json

FROM $BASE_IMAGE as builder
WORKDIR /app
COPY . .
RUN apt update -y \
    && apt install pkg-config libssl-dev -y
# Copy over the cached dependencies
COPY --from=cacher /app/target target
COPY --from=cacher $CARGO_HOME $CARGO_HOME
RUN cargo build --release

FROM gcr.io/distroless/cc-debian10
WORKDIR /app
COPY --from=builder /app/target/release/watchvuln-rs .
CMD ["./watchvuln-rs"]
