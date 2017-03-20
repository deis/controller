FROM quay.io/deis/base:v0.3.6

RUN adduser --system \
	--shell /bin/bash \
	--disabled-password \
	--home /app \
	--group \
	deis

COPY requirements.txt /app/requirements.txt
COPY dev_requirements.txt /app/dev_requirements.txt

RUN buildDeps='gcc libffi-dev libpq-dev libldap2-dev libsasl2-dev python3-dev python3-pip python3-wheel python3-setuptools'; \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        $buildDeps \
        sudo \
        libpq5 \
        libldap-2.4 \
        python3-minimal \
        # cryptography package needs pkg_resources
        python3-pkg-resources && \
    ln -s /usr/bin/python3 /usr/bin/python && \
    mkdir -p /configs && chown -R deis:deis /configs && \
    pip3 install --disable-pip-version-check --no-cache-dir -r /app/requirements.txt && \
    # cleanup
    apt-get purge -y --auto-remove $buildDeps && \
    apt-get autoremove -y && \
    apt-get clean -y && \
    # package up license files if any by appending to existing tar
    COPYRIGHT_TAR='/usr/share/copyrights.tar'; \
    gunzip -f $COPYRIGHT_TAR.gz; tar -rf $COPYRIGHT_TAR /usr/share/doc/*/copyright; gzip $COPYRIGHT_TAR && \
    rm -rf \
        /usr/share/doc \
        /usr/share/man \
        /usr/share/info \
        /usr/share/locale \
        /var/lib/apt/lists/* \
        /var/log/* \
        /var/cache/debconf/* \
        /etc/systemd \
        /lib/lsb \
        /lib/udev \
        /usr/lib/x86_64-linux-gnu/gconv/IBM* \
        /usr/lib/x86_64-linux-gnu/gconv/EBC* && \
    bash -c "mkdir -p /usr/share/man/man{1..8}"

# define execution environment
WORKDIR /app

# test-unit additions to the main Dockerfile
ENV PGBIN=/usr/lib/postgresql/9.5/bin PGDATA=/var/lib/postgresql/data
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        git \
        postgresql \
        postgresql-contrib \
        python3-pip \
        python3-setuptools \
        python3-wheel && \
    pip3 install --disable-pip-version-check --no-cache-dir -r dev_requirements.txt && \
    sudo -u postgres -E $PGBIN/initdb

CMD ["/app/bin/test-unit"]
