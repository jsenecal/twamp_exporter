FROM golang:stretch as confd

ARG CONFD_VERSION=0.16.0

ADD https://github.com/kelseyhightower/confd/archive/v${CONFD_VERSION}.tar.gz /tmp/

RUN apt-get -q update \
  && apt-get -qy install --no-install-recommends bzip2 make \
  && mkdir -p /go/src/github.com/kelseyhightower/confd \
  && cd /go/src/github.com/kelseyhightower/confd \
  && tar --strip-components=1 -zxf /tmp/v${CONFD_VERSION}.tar.gz \
  && go install github.com/kelseyhightower/confd \
  && rm -rf /tmp/v${CONFD_VERSION}.tar.gz \
  && apt-get -qy autoremove \
  && apt-get clean \
  && rm -r /var/lib/apt/lists/*


FROM python:3.7-slim-stretch

COPY --from=confd /go/bin/confd /usr/local/bin/confd

COPY install-clean.sh /usr/local/bin
RUN chmod +x /usr/local/bin/install-clean.sh

ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=DontWarn

RUN install-clean.sh curl gnupg2\
    && curl http://downloads.perfsonar.net/debian/perfsonar-release.list --output /etc/apt/sources.list.d/perfsonar-release.list\
    && curl -SL http://downloads.perfsonar.net/debian/perfsonar-debian-official.gpg.key | apt-key add -\
    && install-clean.sh twamp-client

ARG TWAMP_EXPORTER_VERSION=0.4

RUN mkdir -p /opt/twamp_exporter\
 && curl -SL https://github.com/jsenecal/twamp_exporter/archive/v${TWAMP_EXPORTER_VERSION}.tar.gz \
 | tar -xzC /opt/twamp_exporter --strip-components=1\
 && pip install /opt/twamp_exporter

COPY confd /etc/confd

COPY docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh

EXPOSE 9090

ENTRYPOINT [ "/docker-entrypoint.sh" ]
CMD [ "twamp_exporter" ]