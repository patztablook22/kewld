#! /usr/bin/bash

SYS=$1
TRG=$2
LIB=lib
SRC=src

if [ "$SYS" = "" ]; then
  echo "Usage: $0 package-manager [bin-target]"
  exit 1
fi

if [ "$TRG" = "" ]; then
  TRG="kewld"
fi

if [ ! -f $LIB/$SYS.hpp ]; then
  echo "unsupported libraries"
  exit 1
fi

g++ -std=c++11 \
    $SRC/main.cpp \
    -lpthread \
    -lssl \
    -lcrypto \
    -L/usr/lib \
    -include $LIB/$SYS.hpp \
    -o $TRG

exit $?
