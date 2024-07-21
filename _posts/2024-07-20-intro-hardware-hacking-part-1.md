---
layout: post
title: Intro Hardware Hacking part 1
date: 2024-07-20 22:24 -0400
img_path: /assets/img/IntroHardwareHacking1/
published: true
categories: ["Hardware Challenge","Hack The Box"]
tags: [ "binwalk","SALAE analyzer"]
toc: true
---

This time we will do the Intro to Hardware Hacking track offer by Hack the Box.

## Debugging Interface

We download the files that contain an ``debugging_interface_signal.sal`` file . First time I saw that extension file, and using ``7z l <file.sal>`` we notice it has two files inside.

![FilesInsideACL](image.png)

The meta.json file contains a lot of information in json format, this information seems to be some telemtry realated to the device or to the .bin file 

![JSON_Content](image-1.png)

At the beginning on the digita-0.bin file we notice the string **SALEAE** as a string that doesn't repeat again inside the file.

![SALAE](image-2.png)

Investigation about SALEAE and Hardware come up this [tool](https://www.saleae.com/pages/downloads), SALEAE produce a USB-based logic analyzers to capture and analyze diital signals in electronic systems. Like a oscilloscope but for digital signals (?). 

Asdie for the hardware that SALEAE sell which it allows to capture the signal, we can use his [software](https://support.saleae.com/logic-software/sw-installation#ubuntu-instructions) to view the capture data, so we can deduce that the .acl file is nothing more than a signal capture from SALEA tool.

We notice there is only one channel of data, playing around with the software trying some analyzers, mayor of them requeires more that one channel data, but the **Async Serial** works with just one, so probably the protocol is *UART*

![BIT_RATE](image-4.png)

![analyzers](image-3.png)

Now we need to configure the bit rate, Bit rate is the is the speed at which bits are transmitted in UART communication, measured in bits per second (bps). 

![Bit RATE](image-5.png)

We notice the value 32.02 µs, which is in microseconds so we simply divide it by 1000000 to get the transfer rate by seconds, so 1000000 / 32.02 = 31230.

Now you will see the flag transmitted inside the last bytes trasnmited, start at 1249763920 s.

![Flag](image-6.png)

## The Needle

Again we start running strings command to the .bin file downloaded.

![strings](image-7.png)

mm that xz just remmeber the infameous history of the backdoor.
Continue our recon we ran the ``file`` command.

```sh
file firmware.bin            
firmware.bin: Linux kernel ARM boot executable zImage (big-endian)
```

[Binwalk](https://github.com/ReFirmLabs/binwalk) analyzes binary files, firmware images, and other types of files to identify embedded files and executable code.

![binwalk](image-8.png)

If we launch the machine and try to connect with telnet, we will need a user and a password to login.

![alt text](image-9.png)

Lets grep inside the binwalk dump directory for the "login" string 

![login_grep](image-11.png)

lets see the content of ``/etc/scripts/telnetd.sh`` file 

```sh
#!/bin/sh
sign=`cat /etc/config/sign`
TELNETD=`rgdb
TELNETD=`rgdb -g /sys/telnetd`
if [ "$TELNETD" = "true" ]; then
        echo "Start telnetd ..." > /dev/console
        if [ -f "/usr/sbin/login" ]; then
                lf=`rgbd -i -g /runtime/layout/lanif`
                telnetd -l "/usr/sbin/login" -u Device_Admin:$sign      -i $lf &
        else
                telnetd &
        fi
fi
```

the user is ``Device_Admin`` and the password is inside ``/etc/config/sign`` -> ``qS6-X/n]u>fVfAt!``

![credential_exposed](image-12.png)

## Unique

The description is "We found a car but we are unable to identify if it's the exact one that we have been searching for. The serial network of the car seems intact so we tapped into it and collected some packets. Can you help us find the VIN of the car that is transmitted repeatedly over the network?". 

We download the files and extract the zip file, which is again a ``.sal`` file so directly we upload to SALEAE software.

![Signals](image-13.png)

No idea how to continue, lets try some research on CAR hacking técniques 

* [CAR Hacking 101](https://medium.com/@yogeshojha/car-hacking-101-practical-guide-to-exploiting-can-bus-using-instrument-cluster-simulator-part-i-cd88d3eb4a53)
* [What is VIN](https://en.wikipedia.org/wiki/Vehicle_identification_number#VIN_scanning)

So the protocol is CAN-Bus and a bit rato of 125000 bps we saw the flag transmited in pieces of 64 bytes following the CAN message format.

![CAN-Messge](0_ecOHbJR7Wd9NLPqp.webp)

![CAN-FLAG](image-14.png)

## Secure Digital

Again we are presented with a ``.sal`` file, so directly to SALEAE software anaylzer.
The descriptions ask us about reteive a master key stored on the microSD card, they put the logic capture device in-between, like a MITM on the reading process form the SDcard.

So how to proceed, well investigation found that sdcard use Serial Preipherial Interface **SPI** to comunicated. [SPI](https://support.saleae.com/protocol-analyzers/analyzer-user-guides/using-spi) uses a Clock signal, two data signals (MISO and MOSI), and an Enable signal. That is the most common configuration of SPI, but other variants exist.

![SPI](SPI_single_slave.svg.png)

Studying the SPI communication and some diagrams we can assume that channel 4 is the clock signal, channel 3 is the SS signal because when is low the MISO and MOSI interact sending bytes, and to the rest i just try the two options, channel 1 being MOSI or MISO, thinkl it really doesn't matter. 

![SALEAE](image-15.png)

Inspecting the data in MISO channel, we can search for ``{`` and find the flag.

![HTB{FLAG}](image-16.png)

```text
}\r\nHTB{unp2073c73d_532141_p2070c015_0n_53cu23_d3v1c35}\r\n\0\0\0\0\0\0
```

## Walkie Hackie 

We download the zip and extract four ``.COMPLEX`` files.

![Files](image-17.png)

The description says this files are form a captured transmissions using old walkie-talkies.
Launching the instance we saw a html web page with a comment inside refering this [github](https://github.com/jopohl/urh)

![webpage](image-18.png)

URH allows easy demodulation of signals combined with an automatic detection of modulation parameters making it a breeze to identify the bits and bytes that fly over the air.
Playing around with the tool, i find the preambule and synchronization

![preambule](image-19.png)

For the payload result is diferente from each signal, we just create a new label for that section of the signal

![payload](image-20.png)

1. b1ff57
2. b2ff24
3. a1ff14
4. a2ff84

So the pattern seems ``xxffyy`` being 16 posibilities for each byte, and four diferentes positions $n^{m}=65536, n = 16; m=4$

![bruteForce](image-21.png)
