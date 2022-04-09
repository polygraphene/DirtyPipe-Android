#!/bin/sh
set -e

version=$1
dname="dirtypipe-android-$1"
dir="dist/$dname"

mkdir dist/ || true
mkdir "$dir"

cp dirtypipe-android env-patcher startup-root run.sh run.bat "$dir"

mkdir "$dir"/magisk
for i in magisk busybox magiskboot magiskinit util_functions.sh boot_patch.sh; do
    cp magisk/$i "$dir"/magisk/
done
cp magisk/Magisk-v24.3.apk "$dir"/magisk/

cd dist/
zip -r "$dname".zip "$dname"

