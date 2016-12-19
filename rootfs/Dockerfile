FROM quay.io/deis/base:v0.3.5

RUN adduser --system \
	--shell /bin/bash \
	--disabled-password \
	--home /app \
	--group \
	deis

COPY requirements.txt /app/requirements.txt

RUN buildDeps='gcc git libffi-dev libpq-dev libldap2-dev libsasl2-dev python3-dev python3-pip python3-wheel python3-setuptools'; \
    apt-get update && \
    apt-get install -y --no-install-recommends \
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
    gunzip $COPYRIGHT_TAR.gz; tar -rf $COPYRIGHT_TAR /usr/share/doc/*/copyright; gzip $COPYRIGHT_TAR && \
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

COPY . /app

# define execution environment
WORKDIR /app
CMD ["/app/bin/boot"]
EXPOSE 8000
