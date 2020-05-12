FROM debian:sid

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get dist-upgrade --yes
RUN apt-get install --yes --no-install-recommends build-essential devscripts equivs

ADD [".", "/srv/diffoscope"]
RUN mk-build-deps --install --tool 'apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends --yes' /srv/diffoscope/debian/control

RUN apt-get remove --purge --yes build-essential devscripts equivs
RUN rm -rf /srv/diffoscope/debian

RUN useradd -ms /bin/bash user
USER user
WORKDIR /home/user

ENV PATH="/srv/diffoscope/bin:${PATH}"

ENTRYPOINT ["/srv/diffoscope/bin/diffoscope"]
