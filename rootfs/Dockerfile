FROM quay.io/deis/base:0.2.0

RUN adduser --system \
	--shell /bin/bash \
	--disabled-password \
	--home /app \
	--group \
	deis

COPY . /app

RUN apt-get update \
	&& apt-get install -y \
		gcc \
		git \
		libffi-dev \
		libpq5 \
		libpq-dev \
		python3 \
		python3-dev \
		sudo \
	&& ln -s /usr/bin/python3 /usr/bin/python \
	&& curl -sSL https://bootstrap.pypa.io/get-pip.py | python - pip==8.1.1 \
	&& mkdir -p /configs && chown -R deis:deis /configs \
	&& pip install --disable-pip-version-check --no-cache-dir -r /app/requirements.txt \
	&& apt-get remove -y --auto-remove --purge \
		gcc \
		git \
		libffi-dev \
		libpq-dev \
		python3-dev \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/man /usr/share/doc

# define execution environment
WORKDIR /app
CMD ["/app/bin/boot"]
EXPOSE 8000

ENV WORKFLOW_RELEASE 2.0.0
