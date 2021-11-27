FROM ubuntu:16.04

# prepare packages in env
RUN apt-get update && apt-get -y install libpixman-1-dev curl build-essential debootstrap debian-archive-keyring libjpeg-dev zlib1g-dev unzip wget graphviz curl python-dev python-pip python-virtualenv git wget flex bison libtool automake autoconf autotools-dev pkg-config libglib2.0-dev
RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py && python2 get-pip.py

# fetch qira
RUN git clone https://github.com/geohot/qira.git
WORKDIR /qira

# install python, build qemu, and link qira
RUN pip install --upgrade -r requirements.txt
RUN cd tracers && ./qemu_build.sh
RUN ln -sf /qira/middleware/qira.py /usr/local/bin/qira
