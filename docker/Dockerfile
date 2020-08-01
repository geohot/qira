FROM ubuntu:16.10

# system basics
RUN apt-get update && apt-get -y install build-essential gcc-multilib g++-multilib lib32z1 git curl python python-virtualenv python-dev python3-dev

# qemu deps
RUN apt-get -y install pkg-config zlib1g-dev libglib2.0-dev libpixman-1-dev

# set the workdir to /qira
WORKDIR /qira

# install python venv
RUN virtualenv venv
RUN bash -c 'source venv/bin/activate && pip install --upgrade pip'

# install python deps, this step will be cached
COPY ./requirements.txt ./requirements.txt
RUN bash -c 'source venv/bin/activate && pip install --upgrade -r requirements.txt'

#build qemu and link qira
COPY ./tracers ./tracers
RUN cd tracers && ./qemu_build.sh
RUN ln -sf /qira/qira /usr/local/bin/qira

COPY . .

# test will build Cython qiradb
RUN ./run_tests.sh
