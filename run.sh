#!/bin/sh
set -e

dir=/data/local/tmp
adb=${adb:-"adb"}

$adb push dirtypipe-android env-patcher startup-root magisk/ ${dir}
$adb shell chmod 755 ${dir}/dirtypipe-android ${dir}/env-patcher ${dir}/startup-root ${dir}/magisk/busybox ${dir}/magisk/magiskinit
$adb shell ${dir}/dirtypipe-android

