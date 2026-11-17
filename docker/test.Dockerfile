# Linux build and test environment: the Swift toolchain plus the tools CertKeeper's tests drive
# (the deploy and discovery scripts run locally against fakes).
FROM swift:6.4.2-noble
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 openssl curl openssh-client procps iproute2 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# TrueNAS runs apps as uid/gid 568 ("apps"); tests run as that user too.
RUN groupadd -g 568 apps && useradd -u 568 -g 568 -M -d /tmp/home -s /usr/sbin/nologin apps
