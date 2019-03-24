FROM ubuntu:16.04

# prepare packages in env
RUN apt-get update && apt-get -y install build-essential debootstrap debian-archive-keyring libjpeg-dev zlib1g-dev unzip wget graphviz curl python-dev python-pip python-virtualenv git wget flex bison libtool automake autoconf autotools-dev pkg-config libglib2.0-dev
RUN pip install --upgrade pip

# fetch qira
RUN git clone https://github.com/geohot/qira.git -b cython
WORKDIR /qira

# build qemu
RUN cd tracers && ./qemu_build.sh

# install python packages and link qira
RUN virtualenv venv
RUN bash -c 'source venv/bin/activate && pip install --upgrade -r requirements.txt'
RUN ln -sf /qira/qira /usr/local/bin/qira

