---
layout: post
title: ProxyAsAService
date: 2024-03-05 18:38 -0500
img_path: /assets/img/proxyasaService/
published: true
categories: ["Hack The Box"]
tags: ["Flask", "SSRF","Web Challenge"]
toc: true
---
# Challenge ProxyAsAService

Experience the freedom of the web with ProxyAsAService. Because online privacy and access should be for everyone, everywhere.

We saw some copy of reddit forum, in the url bar capture my atention the param **/url=/r/catpicture** and also appear the web page make some scrapping to original reddit website 
![WebScrapping](image.png)

## Source Code Review
To perfom this source code review i modify some part on the application to attach my VSCode debugger, on run.py file 
```python
from application.app import app
import debugpy

# Configura debugpy para escuchar
debugpy.listen(('0.0.0.0', 5678))
print("⏳ Waiting for debugger attach...")
debugpy.wait_for_client()
print("🚀 Debugger attached!")
  
app.run(host='0.0.0.0', port=1337)
```
On the Dockerfile and build-docker.sh 
```Dockerfile
RUN pip install Flask requests debugpy
EXPOSE 5678
```
```sh
docker run -p 1337:1337 -p 5678:5678 -it --rm --name=web_proxyasaservice web_proxyasaservice
```
now lets follow how the application manage the **url** parameter. This is process by proxy() function on routes.py 
```python
def proxy():
    url = request.args.get('url')
    if not url:
        cat_meme_subreddits = [
            '/r/cats/',
            '/r/catpictures',
            '/r/catvideos/'
        ]
        random_subreddit = random.choice(cat_meme_subreddits)
        return redirect(url_for('.proxy', url=random_subreddit))
    target_url = f'http://{SITE_NAME}{url}'
    response, headers = proxy_req(target_url)

    return Response(response.content, response.status_code, headers.items())
```
If url parameter is not present the application response with some random page of reddit, on the other hand it uses the url to construct the string **traget_url** , Variable SITE_NAME is reddit.com.  It doesn't force the backslash / to make our url be the path, so we can try some domain like reddit.com.attackerdomian.com. target_url is passed to **proxy_req()** function.
```python
def proxy_req(url):    
    method = request.method
    headers =  {
        key: value for key, value in request.headers if key.lower() in ['x-csrf-token', 'cookie', 'referer']
    }
    data = request.get_data()

    response = requests.request(
        method,
        url,
        headers=headers,
        data=data,
        verify=False
    )

    if not is_safe_url(url) or not is_safe_url(response.url):
        return abort(403)
    
    return response, headers
```
Our URL is injected into a request, and the data we pass in the first request are passed to new requests made from the server's point of view, so, SSRF? The only issue is the function is_safe_url(url). Upon inspecting it, we discovered it only compares the URL string against this array: ````['localhost', '127.', '192.168.', '10.', '172.']````. If it doesn't match, it lets it pass.
**But how we get the flag ?**
For that we need to check the other endpoint defined on routes.py 
```python
@debug.route('/environment', methods=['GET'])
@is_from_localhost
def debug_environment():
    environment_info = {
        'Environment variables': dict(os.environ),
        'Request headers': dict(request.headers)
    }

    return jsonify(environment_info)
```
So wee need to make our request from for localhost to "/debug/environment" , we can confirm this connecting to docker and make the request from there.
![Internal](image-1.png)

Our plan is summarized as follows:
1. Pass a payload in the url that evade the reddit.com domain ,something like ```@burpdoamin.com```
2. Bypass the is_safe_url() function in the response, which is why we cannot use ````@localhost````. Perhaps a redirect could work?"

## Local Testing 

We can cirvumvent the reddit.com host using a @ as we can see on next images
![SSRF](image-2.png)
Even we can use a POST request. 

![SSRF_POST](image-3.png)

To bypass **is_safe_url()** we try a redirector hosted on our VPS, but we can't point the redirection to '127.0.0.1:1337/debug/environment' because we will not pass the **is_safe_url(response.url)**
```python
RESTRICTED_URLS = ['localhost', '127.', '192.168.', '10.', '172.']
def is_safe_url(url):
    for restricted_url in RESTRICTED_URLS:
        if restricted_url in url:
            return False
    return True
```
What the developer overlooked is the address '0.0.0.0'
By employing a  [simple python redirector ](https://gist.github.com/shreddd/b7991ab491384e3c3331) on our vps, We set it up to redirect requests to '0.0.0.0:1337/debug/environment'. Additionally, we placed two breakpoints in util.py: one at line 15, if ````request.remote_addr != '127.0.0.1':````, and another at line 35, ````if not is_safe_url(url) or not is_safe_url(response.url):````."

On our VPS 
![VPS-config](image-4.png)
We send our request and first get stop on breakpoint for line 15 , there we can check the value of ```request.remote_addr```
![Bypass_Localhost](image-5.png)
And then will hit the breakpoint for line 35.
![gg](image-6.png)

## Proof of Concept 

![GG_EZ](image-7.png)