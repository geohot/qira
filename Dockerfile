FROM qira:build as qira
WORKDIR /qira
COPY . .
RUN bash -c 'source venv/bin/activate && pip3 install -r requirements.txt'

FROM ubuntu:16.04 as builder
WORKDIR /qira
COPY . .
RUN apt-get update \
    && apt-get -y install \
        build-essential debootstrap debian-archive-keyring \
        libjpeg-dev zlib1g-dev curl unzip graphviz \
        python3-pip python3-dev python-dev python-virtualenv \
        flex bison libtool automake autoconf autotools-dev \
        pkg-config libglib2.0-dev \
    && virtualenv venv \
    && bash -c 'source venv/bin/activate && python3 -m pip install --upgrade pip' \
    && bash -c 'source venv/bin/activate && pip3 install -r requirements.txt' \
    && cd tracers && ./qemu_build.sh && cd /qira \
    && ln -sf /qira/qira /usr/local/bin/qira
VOLUME /qira
EXPOSE 3002
