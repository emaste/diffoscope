FROM debian:sid

ENV DEBIAN_FRONTEND noninteractive

RUN echo deb http://deb.debian.org/debian experimental main >> /etc/apt/sources.list

RUN apt-get update && apt-get dist-upgrade --yes
RUN apt-get install --yes --install-recommends --target-release=experimental diffoscope || apt-get install --yes --install-recommends diffoscope

ENTRYPOINT ["/usr/bin/diffoscope"]
