FROM alpine:latest

RUN apk add --no-cache rust cargo

WORKDIR /app

COPY . .

RUN cargo build --release

CMD ["/app/target/release/fiche-rs"]
