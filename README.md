


```bash
____   _   ____   _   _   ___           _  ___        _________  
| __ ) / | | ___| | | | | / _ \  _ __   | |/ _ \__   _|___ / ___| 
|  _ \ | | |___ \ | |_| || | | || '_ \  | | | | \ \ / / |_ \___ \ 
| |_) || |_ ___) ||  _  || |_| || |_) | | | |_| |\ V / ___) |__) |
|____(_)_(_)____(_)_| |_(_)___(_) .__/  |_|\___/  \_/ |____/____/ 
                                |_|                               
  ____      _    _____          _____                 _ _         
 / ___|   _| |__|___ / _ __ ___|___ /  ___ _   _ _ __(_) |_ _   _ 
| |  | | | | '_ \ |_ \| '__/ __| |_ \ / __| | | | '__| | __| | | |
| |__| |_| | |_) |__) | |  \__ \___) | (__| |_| | |  | | |_| |_| |
 \____\__, |_.__/____/|_|  |___/____/ \___|\__,_|_|  |_|\__|\__, |
      |___/                                                 |___/ 
```
following some nice slow progress




 ```bash
 _   _____  _________   _____
   / | / /   |/_  __/   | / ___/
  /  |/ / /| | / / / /| | \__ \ 
 / /|  / ___ |/ / / ___ |___/ / 
/_/ |_/_/  |_/_/ /_/  |_/____/  
                                
 _       ____________ _____ ______________  ______  ____________  __
| |     / / ____/ __ ) ___// ____/ ____/ / / / __ \/  _/_  __/\ \/ /
| | /| / / __/ / __  \__ \/ __/ / /   / / / / /_/ // /  / /    \  / 
| |/ |/ / /___/ /_/ /__/ / /___/ /___/ /_/ / _, _// /  / /     / /  
|__/|__/_____/_____/____/_____/\____/\____/_/ |_/___/ /_/     /_/   
```                                                                    

# Natas Web Security

## Overview

Natas is an overthewire wargame that give practical labs for people to practice there web security skills it consists of many levels where one has to find the  password for the next level by solving the previous level but al passwords are llocated in the /etc/natas_webpass/ directory 


### Natas0-1
 - In this level one has to analyze the source code of the website in order to find the password for level 1...Funny enough the password is just located in the comment section of the source code

### Natas 1-2
 - There are parts of the container in the web page where one is not able to right click on but there is others you can right-click on and the password is located in the comment section just like in natas0

### Natas 2-3
 - In thi level one is required to analyze the sorce code ...there is a dirrectory that is listed in the source code that one can easily access it.In the directory there are two files pixel.png and users.txt,the users.txt contains the credentials that can be used to access level3's password

### Natas3-4 
 - In this level you will learn about web crawlers such as roborts.txt file that one can be able to access it in the website if it is allowed.The file contains details of the allowed and disallowed directories that can be accessed.In this level one is required to access the robots.txt file which has a disallowed directory listed that can be exploited in order to get the passsword for level 4(s3cr3t is the disallowed directory)

### Natas4-5
 - In this level, first tools of exploiting websites are introduced.One can use either burpsuite or owasp zap to intercept a web request.Here ou will need to refresh the page in oreder to require a referer,that is  "You are visiting from "http://natas4.natas.labs.overthewire.org/" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/"" the following text will be displayed after refreshiing the page ...here you will be needed to chanege the referer to natas5 after intercepting the request and resending the request again in order to get the passwotd for the next leve
   


- In the next levels from 5 - 10 we wil be required to understand some common web vulnerabilities such as LFI(Local file inclusion),command injections and also authentication vulnerability

### Natas5-6
- IN this level we will be exploiting authentication vulnerability using either burpsuite or owasp zap.After intercepting the request,one is required to change the loggedin status to 1 and resend the request in oreder to get the password for level 6

### Natas6-7
- here we are explooiting a simple LFI vulnerability where a file is shown in the source code '/includes/secret.inc' you will have to access this file which contains a  secret word that you are required to input in the input box and the n submit it  in order to be provided with the password for level 7

### Natas7-8
- the webpage provides us with a home page and about page, in which each page gives us a hint that the password for level 8 is contained in the /etc/natas_webpass/natas8 file.The vulnerability being exploited in this level is LFI where the input is not sanitized in any way, therefore you can access the file easily by simply adding the path to the file staright into the url i.e, ...page=/et/natas_webpass/natas8

### Natas8-9
- After analyzing the source code we realize that there is a secret encoded in hexform them converted to binary then encoded in base64,afterwards is reversed

```php
encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}
```
You will be required to use cyberchef in order to decode the secret word from hex then reverse it then decode the base64 found and then put the result found into the input box then sumit it to get the password for level 9

### Natas9-10
- Finally,in this level we will be able to do a command injection where the server is unix based therefore on e will be able to run unix based commands to be able to iist items in the website such as dictionary.txt and be able to cat(concatenate) /etc/natas_webpass/natas10 file and be able to acquire the password for level10

### Natas 10 -11
- Here ther is an LFI vulnerability but with sanitization,on viewing the source code ..we are not able to use special characters such as ;/&\|,after researching for the cheatsheets,the  special character that can be used include '%0Acat%20' in order to access the password file to obtain password for level 11

### Natas11 - 12
- Here we will be dealing with cookies,further more cookies that are XOR encrypted,here we are required to write a python script that will enable us to be able to send our edited cookie that will be obtained from our php script,the python script used is as one used below

```python
#!/usr/bin/env python
#-*- coding: utf-8 -*-

import requests
import re 
import urllib
import base64

username = 'natas11'
password = '1KFqoJXi6hRaPluAmk8ESDW4fSysRoIg'

url = 'http://%s.natas.labs.overthewire.org/' %username

session = requests.Session()
#response = session.get(url, auth = (username,password))
cookies = {"data" : "MGw7JCQ5OC04PT8jOSpqdmk3LT9pYmouLC0nICQ8anZpbS4qLSguKmkz"}
response = session.get(url, auth = (username,password),cookies = cookies)

#print (base64.b64decode(urllib.parse.unquote(session.cookies['data'])).hex())

content = response.text
print (content)
```
- in the above script we have imported some libraries and set our username and password and be able to access the website using the url variable that is already set.the session variable is then used to call the function session() from requests class that will set a session cookkie for us,cookies variable is then given a cookie that is obtained from our php script,respponse is then set such that it will provide us with the web page and cookie provided set manually then it is printed out using the print function, displaying the password for level12
Below is the php script l used
```php
#!/usr/bin/php8.2
<?php
$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

function xor_encrypt($in, $key) {
    
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}
$plaintext = json_encode($defaultdata);
$ciphertext = hex2bin('306c3b242439382d383d3f23392a6a766920276e676c2a2b28212423396c726e68282e2a2d282e6e36');
$key = 'KNHL';
//echo(xor_encrypt($plaintext,$ciphertext));

$good_data = array("showpassword"=>"yes","bgcolor"=>"#ffffff"); 

$good_plaintext = json_encode($good_data);
$good_ciphertext = xor_encrypt($good_plaintext, $key);

$cookie = base64_encode($good_ciphertext);

echo($cookie);


?>
```


This code is a PHP script that defines a function `xor_encrypt()` and uses it to perform an XOR encryption on some data. Here is a line-by-line explanation of the code:

```
#!/usr/bin/php8.2
```

This line specifies the interpreter that should be used to execute the script.

```php
$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");
```

This line creates an associative array with two key-value pairs.

```php
function xor_encrypt($in, $key) {
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}
```

This code defines a function named `xor_encrypt()` that takes two arguments: `$in` (the input text to encrypt) and `$key` (the encryption key). The function iterates over each character of the input text and XORs it with the corresponding character in the key, using the modulus operator (`%`) to cycle through the key if necessary. The result of the XOR operation is concatenated to the output string, which is returned when the loop is finished.

```python
$plaintext = json_encode($defaultdata);
$ciphertext = hex2bin('306c3b242439382d383d3f23392a6a766920276e676c2a2b28212423396c726e68282e2a2d282e6e36');
$key = 'KNHL'; //this is the key l got after doing a json encode
```

These lines create a plaintext string by encoding the `$defaultdata` array as JSON, and then create a ciphertext string by converting a hexadecimal string to binary. The key used for encryption is set to the string "KNHL".

```php
$good_data = array("showpassword"=>"yes","bgcolor"=>"#ffffff"); 
$good_plaintext = json_encode($good_data);
$good_ciphertext = xor_encrypt($good_plaintext, $key);
```

These lines create a new data array with a "showpassword" value of "yes", and then encode it as JSON to create a plaintext string. The plaintext string is then encrypted using the `xor_encrypt()` function and the key set earlier.

```php
$cookie = base64_encode($good_ciphertext);
echo($cookie);
```

These lines encode the encrypted data as base64 and print the resulting string to the console. The output is the value of the cookie that could be used by a web application. 
