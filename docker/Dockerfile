FROM ubuntu:24.04

# system basics
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install \
  build-essential gcc-multilib g++-multilib lib32z1 git curl \
  python3 python3-venv python3-dev python3-pip

# qemu deps
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install pkg-config zlib1g-dev libglib2.0-dev libpixman-1-dev

WORKDIR /qira

# install python venv
RUN python3 -m venv venv
RUN bash -c 'source venv/bin/activate && python -m pip install --upgrade pip setuptools wheel'

# install python deps, this step will be cached
COPY ./requirements.txt ./requirements.txt
RUN bash -c 'source venv/bin/activate && python -m pip install --upgrade -r requirements.txt'

#build qemu and link qira
COPY ./tracers ./tracers
RUN cd tracers && ./qemu_build.sh
RUN ln -sf /qira/qira /usr/local/bin/qira

COPY . .

# test will build Cython qiradb
RUN ./run_tests.sh
