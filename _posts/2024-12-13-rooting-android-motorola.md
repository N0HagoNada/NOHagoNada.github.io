---
layout: post
title: Rooting Android Motorola
date: 2024-12-13 00:22 -0500
img_path: /assets/img/rootMotog41/
published: true
categories: ["Mobile Challenge"]
tags: ["Motorola g41", "Magisk Rooting"]
toc: true
---


I will show how to root a motorola g41 device 

## Prepare the devices

1. Enable developer mode going to "Configuration" -- "About phone" -- touch seven times the last option called "Build number" 
2. Now in the "System" / advance options you will saw the "{ } Developer options", there you have to enable "OEM unlocking" and "USB debugging" 

## Unlock the bootloader

1. You need to install [ADB and Fastboot](https://developer.android.com/studio/releases/platform-tools) in your PC
2. Now enter the [this](https://en-us.support.motorola.com/app/standalone/bootloader/unlock-your-device-b) page and login with an account.
3. run `` adb reboot bootloader``
4. run ``fastboot oem get_unlock_data``
5. If you get stuck on *< waiting for any device >* message its because you need to install [Motorola USB Drivers](https://en-us.support.motorola.com/app/answers/detail/a_id/88481), so we download the Drivers for Windows and now if run ``fastboot devices`` we saw our moto g41

![alt text](image.png)

6. Put the code in [this](https://en-us.support.motorola.com/app/standalone/bootloader/unlock-your-device-b) webpage, accept the conditions and check if you devices is unlockable
7. Now you will receive an email with the key to unlock the bootloader
8. now run ``fastboot.exe oem unlock <Your-key>``
9. Accept on the device and voila

![unlocked](image-1.png)

## Rooting the device

1. install [Magis manager app](https://github.com/topjohnwu/Magisk/releases/) `` adb install .\app-release.apk`` 
2. Download the motorola firmware, for that we will use the [Software Fix](https://support.lenovo.com/co/es/downloads/ds101291) tool from Lenovo
3. Install and connect the device, wait until the Software recongnizes the phone throw adb
4. Inside the Software Fix application go to the Rescue tab and download the zip file, important chech that the actual version is the same as the destiny firmware version
5. look for the **boot.img** file in the path ``C:\ProgramData\RSA\Download\RomFiles\XXX``
6. Push the file into the phone ``adb push .\boot.img /storage/sdcard0/Download/`` 
7. Open the magisk manager app and click on Install, then choose the "Select and Patch a File" with the boot.img file we already push it

![patched_img](InkedMagisk-patch-boot-image_LI.jpg)

8. Copy the patched image to the PC with adb pull
9. Now we can [flash](https://topjohnwu.github.io/Magisk/install.html) the device with the new rooted image
```sh
adb reboot bootloader
fastboot flash boot /path/to/magisk_patched_[random_strings].img
```
10. voila

![rooted](image-2.png)