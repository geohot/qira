#!/bin/bash

build_base() {
    echo "building qira/qira:build docker image"
    docker build -t qira:build --target builder .
}

build_qira() {
    echo "building qira/qira:latest image"
    docker build -t qira:latest --cache-from qira:build --target qira .
}

build_all() {
    build_base
    build_qira
}

if [ "$1" == "base" ] ; then
    build_base
elif [ "$1" == "qira" ] ; then
    build_qira
else
    build_all
fi
