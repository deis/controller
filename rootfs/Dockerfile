FROM alpine:3.3

# install common packages
RUN apk add --update-cache curl bash openssl sudo && rm -rf /var/cache/apk/*

# define execution environment
CMD ["/app/bin/boot"]
EXPOSE 8000

# define work environment
WORKDIR /app

ADD build.sh /app/tmp/build.sh

ADD requirements.txt /app/requirements.txt

RUN DOCKER_BUILD=true /app/tmp/build.sh && rm -rf /app/*

ADD . /app

ENV WORKFLOW_RELEASE 2.0.0-dev
