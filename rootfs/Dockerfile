FROM alpine:3.2

# install common packages
RUN apk add --update-cache curl bash openssl sudo && rm -rf /var/cache/apk/*

# define execution environment
CMD ["/bin/boot"]
EXPOSE 8000

COPY . /

WORKDIR /app

RUN build

RUN python manage.py collectstatic --settings=deis.settings --noinput

ENV DEIS_RELEASE 1.13.0-dev
