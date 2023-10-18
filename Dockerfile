FROM ubuntu:22.04


RUN apt update
RUN apt install -y iputils-ping iproute2

ARG RELEASE=debug
COPY target/${RELEASE}/geopacket /
COPY data/ips.txt /

ENV RUST_LOG=debug

CMD ["/geopacket"]
