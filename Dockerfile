FROM debian:sid

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt dist-upgrade --yes
RUN apt install --yes --no-install-recommends devscripts equivs

ADD [".", "/srv/diffoscope"]
RUN mk-build-deps --install --tool 'apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends --yes' /srv/diffoscope/debian/control

RUN apt remove --purge --yes devscripts equivs
RUN apt autoremove --purge --yes

ENTRYPOINT ["/srv/diffoscope/bin/diffoscope"]
