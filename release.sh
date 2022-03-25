#!/bin/sh
set -e

version=$1
dname="dirtypipe-android-$1"
dir="dist/$dname"

mkdir dist/
mkdir "$dir"

cp dirtypipe-android startup-root run.sh run.bat "$dir"

mkdir "$dir"/magisk
cp magisk/busybox "$dir"/magisk/
cp magisk/magiskpolicy "$dir"/magisk/

cd dist/
zip -r "$dname".zip "$dname"

