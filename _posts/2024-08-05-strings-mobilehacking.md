---
layout: post
title: Strings MobileHacking
date: 2024-08-05 18:00 -0400
img_path: /assets/img/stringsMBC/
published: true
categories: ["Mobile Challenge","Mobile Hacking Lab"]
tags: ["Exploit exported activities", "Static analysis", "Frida", "Memory Dump"]
toc: true
---
# Mobile Hacking Lab

This time we will take the [strings](https://www.mobilehackinglab.com/course/lab-strings) challenge on Mobile Hacking lab.

We connect through adb via openvpn file and try to list the activites from the string application ``com.mobilehackinglab.challenge``.
Extract the path of the application

```sh
adb shell pm path com.mobilehackinglab.challenge
package:/data/app/~~p_54bM-A63QkAZxdaHHILQ==/com.mobilehackinglab.challenge-AfKKIwpsKTgv5lPYwRWv0Q==/base.apk
```

Extract the apk file

```sh
adb pull /data/app/~~p_54bM-A63QkAZxdaHHILQ==/com.mobilehackinglab.challenge-AfKKIwpsKTgv5lPYwRWv0Q==/base.apk
```

Then we can analyze the **AndroidManifest.xml** file

- Find one activity besides the MainActivity exported explicity and with a *intent-filter*.
- A receiver with the exported tag on true and four *intent-filter* defined inside.

![Activity2](image.png)

## Activity2

This activity has a intent-filter which are object to request an accion to other components in the application, it help with the comunication between components through three diferentes ways.
1. Launch an Activity
2. Initialize a Service
3. Transmit an event. 

Intent require an **action** which specifies the generic action to be executed ( *ACTION_VIEW* or *ACTION_SEND* ).

It also use **Data**, which make reference to the data that the action would require or the data type (MIME), like this case ``android:schema`` and ``android:host``. 

The category contains aditional information about the component type that control the intent, for example *CATEGORY_BROWSABLE* allows to be initialize for a web browser to show data like images or emails messages.

The source code of the Activity2 

```java
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_2);
        SharedPreferences sharedPreferences = getSharedPreferences("DAD4", 0);
        String u_1 = sharedPreferences.getString("UUU0133", null);
        boolean isActionView = Intrinsics.areEqual(getIntent().getAction(), "android.intent.action.VIEW");
        boolean isU1Matching = Intrinsics.areEqual(u_1, cd());
        if (isActionView && isU1Matching) {
            Uri uri = getIntent().getData();
            if (uri != null && Intrinsics.areEqual(uri.getScheme(), "mhl") && Intrinsics.areEqual(uri.getHost(), "labs")) {
                String base64Value = uri.getLastPathSegment();
                byte[] decodedValue = Base64.decode(base64Value, 0);
                if (decodedValue != null) {
                    String ds = new String(decodedValue, Charsets.UTF_8);
                    byte[] bytes = "your_secret_key_1234567890123456".getBytes(Charsets.UTF_8);
                    Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
                    String str = decrypt("AES/CBC/PKCS5Padding", "bqGrDKdQ8zo26HflRsGvVA==", new SecretKeySpec(bytes, "AES"));
                    if (str.equals(ds)) {
                        System.loadLibrary("flag");
                        String s = getflag();
                        Toast.makeText(getApplicationContext(), s, 1).show();
                        return;
                    }
```

1. We need to launch the intent with the specific action ``android.intent.action.VIEW``
2. The string ``u_1`` from the sharedPreferences has to be the same as the result of the ``cd()`` function.
3. The data schema and host have to be ``mhl`` and ``labs`` so ``mhl://labs/<b64Value>``
4. The b64data passed is compared with a cipher text.


## Trigger intents

We can trigger intents via adb, this case with this command. But as we don't know the ds correct value the screen close immediately.
```sh
adb shell am start -a android.intent.action.VIEW -d "mhl://labs/base64data" -n com.mobilehackinglab.challenge/.Activity2
```
We saw hardcoded in the code all the data ( secrets, IV,etc ) being able to reproduce the decrypt process.

![BASE64DATA](image-1.png)

## SharedPreferences 

Who create the sharedPreferences ``DAD4``?, looking at the MainActivity code we found the KLOW function

```java
    public final void KLOW() {
        SharedPreferences sharedPreferences = getSharedPreferences("DAD4", 0);
        SharedPreferences.Editor editor = sharedPreferences.edit();
        Intrinsics.checkNotNullExpressionValue(editor, "edit(...)");
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy", Locale.getDefault());
        String cu_d = sdf.format(new Date());
        editor.putString("UUU0133", cu_d);
        editor.apply();
    }
```

We can launch this function with Frida hooking the MainActivity 

```javascript
Java.perform(function (){
    setTimeout(function (){
        Java.choose('com.mobilehackinglab.challenge.MainActivity',{
            onMatch: function(instance){
                console.log("Creating SharedPreferences");
                instance.KLOW();
            },
            onComplete: function(){}
        });
    },1000);
})
```

We can combine this two options to pass all the `If` statements.

![Succes](image-2.png)

We saw a success message, but no flag :( ? 

## DUMP Memory

We can scan memory with frida as mention [here](https://8ksec.io/advanced-frida-usage-part-7-frida-memory-operations/) 

First we need to hook the library memory base address.

![Library_memorybase](image-3.png)

Define our pattern to search ``let pattern = 4d 48 4c`` for **MHL**.

![Dumped](image-4.png)

Now we need to read the value on that memory using [Memory.scanSync](https://frida.re/docs/javascript-api/#memory)

```javascript
Java.perform(function (){
     setTimeout(function (){
        const libflag = Process.getModuleByName('libflag.so');

        // Pattern MHL
        let pattern = "4d 48 4c"

        console.log("Base address: " + libflag.base);
        console.log("Size in memory: " + libflag.size);

        // Memory.scan(address, size, pattern, callback)
        Memory.scan(libflag.base, libflag.size, pattern, {
            onMatch: function (address) {
                // Successful Match Message
                console.log("Match at: " + address);
            },
            onComplete: function () {
                // Scan complete Message
                console.log("Scan complete");
            },
            onError: function (error) {
                console.log("Scan error:" + error);
            },
        });

        const results = Memory.scanSync(libflag.base, libflag.size, pattern);
        console.log('Memory.scanSync() result:\n' + JSON.stringify(results));
        const flag_addr = results[0].address;
        console.log(hexdump(flag_addr,{length: 30}));
     },1000);
})
```

![FLAG](image-5.png)