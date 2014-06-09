#!/bin/sh

BASE_DIR=$(cd "$(dirname "$0")"; pwd)
PROTO_DIR=/tmp/kinetic-protocol
PROTO=https://raw.githubusercontent.com/Seagate/kinetic-protocol/master/kinetic.proto
#PROTO=https://raw.githubusercontent.com/Seagate/kinetic-protocol/9c6b4a180a70f8488c5d8ec8e8a6464c4ff63f84/kinetic.proto

mkdir $PROTO_DIR
wget $PROTO -O $PROTO_DIR/kinetic.proto
protoc -I $PROTO_DIR --python_out=$BASE_DIR/kinetic $PROTO_DIR/kinetic.proto
