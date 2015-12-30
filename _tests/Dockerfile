FROM ubuntu-debootstrap:14.04

COPY _tests.test .
RUN mv _tests.test /bin
RUN apt-get update -y && apt-get install -y curl
RUN curl -sSL http://deis.io/deis-cli/install-v2-alpha.sh | bash && mv ./deis /bin/deis
CMD _tests.test
