#!/bin/bash

BUILD=$1
pkgbuild --root `pwd`/root --scripts pkgbuild-scripts --identifier com.zdziarski.FlockFlock --version $BUILD --ownership recommended --install-location / --sign "Jonathan Zdziarski" FlockFlock-$BUILD.pkg

#codesign -fs "Mac Developer: Jonathan Zdziarski" FlockFlock-$BUILD.pkg
