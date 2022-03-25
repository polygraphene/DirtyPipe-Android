#!/bin/sh
set -e

version=$1
dname="dirtypipe-android-$1"
dir="dist/$dname"

mkdir dist/ || true
mkdir "$dir"

cp dirtypipe-android startup-root run.sh run.bat "$dir"

mkdir "$dir"/magisk
cp magisk/busybox "$dir"/magisk/
# magiskpolicy is an applet of magiskinit
cp magisk/magiskinit "$dir"/magisk/magiskpolicy

cd dist/
zip -r "$dname".zip "$dname"

