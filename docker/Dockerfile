FROM ubuntu:16.04

# prepare packages in env
RUN apt-get update && apt-get -y install build-essential debootstrap debian-archive-keyring libjpeg-dev zlib1g-dev unzip wget graphviz curl python-dev python-pip python-virtualenv git wget flex bison libtool automake autoconf autotools-dev pkg-config libglib2.0-dev
RUN pip install --upgrade pip

# fetch qira
RUN git clone https://github.com/geohot/qira.git
WORKDIR /qira

# install python packages, build qemu, and link qira
RUN pip install --upgrade -r requirements.txt
RUN pip install --upgrade ./qiradb
RUN cd tracers && ./qemu_build.sh
RUN ln -sf /qira/middleware/qira.py /usr/local/bin/qira

