FROM rust:alpine as build

RUN apk add --no-cache rust cargo

WORKDIR /app

COPY . .

RUN cargo build --release

FROM alpine:latest as runtime

COPY --from=build /app/target/release/fiche-rs .
RUN pwd && ls -al

CMD ["/fiche-rs"]
