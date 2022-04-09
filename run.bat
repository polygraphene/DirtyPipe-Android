@echo off

set dir=/data/local/tmp
set adb=adb -d

%adb% push dirtypipe-android env-patcher startup-root magisk/ %dir%
%adb% shell chmod 755 %dir%/dirtypipe-android %dir%/env-patcher %dir%/startup-root %dir%/magisk/busybox %dir%/magisk/magiskinit
%adb% shell %dir%/dirtypipe-android

pause

