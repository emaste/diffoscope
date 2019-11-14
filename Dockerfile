FROM debian:sid

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get dist-upgrade --yes
RUN apt-get install --yes --no-install-recommends devscripts equivs

ADD [".", "/srv/diffoscope"]
RUN mk-build-deps --install --tool 'apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends --yes' /srv/diffoscope/debian/control

RUN apt-get remove --purge --yes devscripts equivs
RUN apt-get autoremove --purge --yes

ENV PATH="/srv/diffoscope/bin:${PATH}"

ENTRYPOINT ["/srv/diffoscope/bin/diffoscope"]
