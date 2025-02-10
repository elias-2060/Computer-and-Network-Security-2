# HTTP MAC Spec

This spec documents a MAC authentication format for securing HTTP traffic. It is unofficial and solely for educational
purposes in the Computer and Network Security course at the University of Antwerp.

## Overview of Request and Response Headers

### Client
The HTTP client authenticates the request by adding the following HTTP headers:

```
Authorization : <Authorization>
X-Authorization-Timestamp : <Unix Timestamp In Seconds>
```

The HTTP client must **not** add the following HTTP Header to the request: \
X-Authenticated-Id (reserved for internal server to server communication)

### Server

If the server authenticates the request successfully, it will add the following HTTP headers to the response:

```
Authorization: <Authorization>
X-Authorization-Timestamp : <Unix Timestamp In Seconds>
```

The client should verify the response MAC which authenticates the response body back from the server.

### Unauthorized

If client or server cannot authenticate the received HTTP message, they will send a response consisting of:

```
Code : 401
Body : 'Not authorized' if server, 'Server response not authorized' if client
Headers : ResponseHeaders
```

With the ResponseHeaders being:

```
Content-Type : 'text/html'
Date : datetime in '%a, %d %b %Y %H:%M:%S %Z' format
Connection: 'close'
WWW-Authenticate : SupportedAuthenticationAlgorithmName [ + "," + SupportedAuthenticationAlgorithmName, for all other supported authentication methods]
```

## Overview of Authorization Header and MAC

The pseudocode below illustrates construction of the HTTP "Authorization" header and MAC:

```
Authorization = AlgorithmName + " " +
                "keyid=" + DoubleQuoteEnclose( KeyingIdentificationMaterial ) + "," +
                "nonce=" + DoubleQuoteEnclose( Nonce ) + "," +
                "headers=" + DoubleQuoteEnclose( HeaderNames ) + "," +
                "mac=" + DoubleQuoteEnclose( MAC ) 

HeaderNames = "" or
    HTTP-Header-Name [ + ";" + HTTP-Header-Name, for all other headers in HTTP message]
    (sorted alphabetically)
                
MAC = HEXSTRING( HASHED ( SecretKey, Nonce, StringToAuth ) )

StringToAuth = [ HTTP-Verb + "\n" + , if HTTP request]
   [ Host + "\n" + , if HTTP request]
   [ Path + "\n" + , if HTTP request]
   Headers
   [ + "\n" + Content, if Content-Length > 0 ]
   
Headers = Lowercase( HTTP-Header-Name ) + ":" + HTTP-Header-Value 
   [ + "\n" + Lowercase( HTTP-Header-Name ) + ":" + HTTP-Header-Value, for all other headers in HTTP message]
   ( must be in the same order as HeaderNames )

```

note that content is encrypted since sha512hmac is chosen as authentication method.

The **authentication related headers should be included** in "Headers" and "HeaderNames". The MAC must be added to the "Authorization" header after creating it.

### Authorization Header

The value of the `Authorization` header contains the following attributes:

* `keyid`: The key's unique identifier
* `nonce`:  The used nonce in the generation of the MAC
* `headers`: A **sorted** list of all HTTP headers that are included and used in the MAC base string. These are separated with ";"
* `MAC`: The Message Authentication Code (in hex-string format) as described below.

Each attribute value should be enclosed in double quotes.

Note that the name of this (standard) header is misleading - it carries authentication information.

#### MAC

The MAC is a hashed hexdigest (hex-string format) generated from the following parts:

* `SecretKey`: The used secret key
* `Nonce`: A random value of length equal to the blocksize of the used hashing algorithm
* `StringToAuth`: The string being hashed as described below

#### Secret Key

The secret key that is used can be of any size bigger than 8 bits.

#### String To Authenticate

The base string is a concatenated string generated from the following parts:

* `HTTP-Verb`: The uppercase HTTP request method e.g. "GET", "POST". Not present with an HTTP response.
* `Host`: The HTTP request hostname. Not present with an HTTP response.
* `Path`: The HTTP request path with leading slash, e.g. `/resource/11`. Not present with an HTTP response.
* `Headers`: The header names and values specified as in the header's parameter (same order) of the Authorization header. Names should be lowercase, separated from value by a colon and the value followed by a newline so each extra header is on its own line. If there are no added signed headers, an empty line should **not** be added to the signature base string.
* `Content`: The bytestring of the raw body of the HTTP message that has a body. Omit if Content-Length is 0.
  
#### X-Authorization-Timestamp Header

A Unix timestamp (**integer** seconds since Jan 1, 1970 UTC). If this value differs by more than 900 seconds (15 minutes) from the time of the server, the request will be rejected.

#### X-Authenticated-Id Header

If the X-Authenticated-Id is present in the message, the client implementing the validation of the message should **reject** the message and return "unauthenticated". This header is reserved for servers or proxies who want to validate messages and forward messages to backends. Backends can read this added header to understand if it was authenticated. Use this with caution and careful consideration as adding this header only guarantees it was authenticated to that ID.

### Example
```
Authorization:  sha512hmac 
                keyid="01",
                nonce="Ob8D5gPCAvwg6PplKOTIa5NrHiufn5gAzBkpVwIm2XXhgX5A5C8s8ahkVVUQbyFcBSLKkOG47pOrI2WvTER0UYihbZPm4paCiYBErukfnVRo1goTYazrZan60Vcj2mDs",
                headers="Accept;Accept-Encoding;Accept-Language;Authorization;Connection;Content-Encoding;Content-Length;Content-Type;Cookie;Encryption;Host;Origin;Priority;Referer;Upgrade-Insecure-Requests;User-Agent;X-Authorization-Timestamp",mac="123363944d0de0d5bf196ef738360a416ab75b8ed4b17c740608f38beb5824e6270590ed51d5aa4ca1730bc6350324df040cac12668cfd235f4d0568c504cefb" 
StringToAuth:   b'POST\n
                cns_flaskr\n
                /add\n
                accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\naccept-encoding:gzip, deflate, aes256cbc\naccept-language:en-US,en;q=0.5\nauthorization:sha512hmac keyid="01",nonce="Ob8D5gPCAvwg6PplKOTIa5NrHiufn5gAzBkpVwIm2XXhgX5A5C8s8ahkVVUQbyFcBSLKkOG47pOrI2WvTER0UYihbZPm4paCiYBErukfnVRo1goTYazrZan60Vcj2mDs",headers="Accept;Accept-Encoding;Accept-Language;Authorization;Connection;Content-Encoding;Content-Length;Content-Type;Cookie;Encryption;Host;Origin;Priority;Referer;Upgrade-Insecure-Requests;User-Agent;X-Authorization-Timestamp"\nconnection:keep-alive\ncontent-encoding:aes256cbc\ncontent-length:32\ncontent-type:application/x-www-form-urlencoded\ncookie:session=eyJsb2dnZWRfaW4iOiJ1MSJ9.ZqzmOw.NHtcWaxsY0AE250NOBF4CJGK8bk\nencryption:keyid="01"; nonce="yHdfQlWsIJ4Qh4qb"\nhost:cns_flaskr\norigin:http://cns_flaskr\npriority:u=1\nreferer:http://cns_flaskr/\nupgrade-insecure-requests:1\nuser-agent:Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0\nx-authorization-timestamp:1722607168\n
                v\x1d\xcaQ.\xee\x02\xb9\x99\x1f\x84|\xbf\xa02\xf9\x8c\xbd\xf0rMd\xae\xa8\xda\xa8[}\xa7\xf0\x15b'
```
