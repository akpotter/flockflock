#!/bin/bash

BUILD=$1

if [ "$1x" == "x" ]
then
    echo "syntax: $0 [build_number]"
    exit
fi
IDENTITY="Jonathan Zdziarski"

pkgbuild --root `pwd`/root --scripts pkgbuild-scripts --identifier com.zdziarski.FlockFlock --version $BUILD --ownership recommended --install-location / --sign "$IDENTITY" FlockFlock-$BUILD.pkg
