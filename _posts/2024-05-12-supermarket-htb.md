---
layout: post
title: Supermarket HTB
date: 2024-05-12 13:53 -0400
img_path: /assets/img/supermarketHTB/
published: true
categories: ["Mobile Challenge","Hack The Box"]
tags: ["Frida","Cipher AES","dinamic analysis"]
toc: true
---
# Mobile Challenge
My supermarket list is too big and I only have $50. Can you help me get the Discount code?

## Source code review 
Looking at the soruce code form MainAcitvity, when we try to submit a cupon
```java
        public void onTextChanged(CharSequence charSequence, int i2, int i3, int i4) {
            try {
                String obj = MainActivity.this.f2075q.getText().toString();
                MainActivity mainActivity = MainActivity.this;
                String stringFromJNI = mainActivity.stringFromJNI();
                Objects.requireNonNull(mainActivity);
                SecretKeySpec secretKeySpec = new SecretKeySpec(mainActivity.stringFromJNI2().getBytes(), mainActivity.stringFromJNI3());
                Cipher cipher = Cipher.getInstance(mainActivity.stringFromJNI3());
                cipher.init(2, secretKeySpec);
                int i5 = 0;
                if (!obj.equals(new String(cipher.doFinal(Base64.decode(stringFromJNI, 0)), "utf-8"))) {
                    MainActivity.this.f2081w.clear();
                    MainActivity.this.f2076r = 5.0d;
                    while (true) {
                        String[] strArr = this.f2085c;
                        if (i5 >= strArr.length) {
                            break;
                        }
                        MainActivity.this.f2081w.add(strArr[i5]);
                        i5++;
                    }
```
where comes those stringFromJNIX().
```java
    static {
        System.loadLibrary("supermarket");
    }
    public native String stringFromJNI();

    public native String stringFromJNI2();

    public native String stringFromJNI3();
```
So we can make this CTF by two ways:

- [x] An easy way, hooking the crypto library *javax.crypto.Cipher* 
- [ ] Reversing the libsupermarket.so whith ghidra, and find there the value for the Key, the iv and the flag. 

## Local Testing

Found a good crypto hook in frida library codes [here](https://codeshare.frida.re/@Serhatcck/java-crypto-viewer/), just run it 

```bash
frida -U -f com.example.supermarket --codeshare Serhatcck/java-crypto-viewer
```
then enter whatever you want on the cupon text field. 

## Proof of Concept

**Doing it the easy way.** 

![gg_flag](image-1.png)