FROM ubuntu:16.04

# minimal system basics
RUN apt-get update
RUN apt-get -y install git curl python

# fetch qira
RUN git clone https://github.com/geohot/qira.git
WORKDIR /qira

# build qemu
RUN apt-get -y install build-essential pkg-config zlib1g-dev libglib2.0-dev libpixman-1-dev
RUN cd tracers && ./qemu_build.sh

# install python packages and link qira
RUN apt-get -y install python python-virtualenv python-dev
RUN virtualenv venv
RUN bash -c 'source venv/bin/activate && pip install --upgrade pip'
RUN bash -c 'source venv/bin/activate && pip install --upgrade -r requirements.txt'
RUN ln -sf /qira/qira /usr/local/bin/qira

# test will build Cython qiradb
RUN ./run_tests.sh

