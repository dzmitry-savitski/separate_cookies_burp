# Burp extention for separating cookies on different headers

## Problem:
Nginx has a limited header length. Burp Suite merges all cookies into one long header, so nginx replies with error:
```
400 Bad Request
Request Header Or Cookie Too Large
```

## Solution:
Create a separate header for each cookie
