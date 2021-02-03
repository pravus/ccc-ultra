# go-httpd

## Overview

go-httpd - A simple HTTP service for serving files from the current directory tree.

## Usage

```
# serve files from the current directory via http://localhost:8080/
go-httpd

# serve files via http://hostname:5000/
go-httpd -http :5000

# set the bind address via environment variables
HTTP_BIND=:5000 go-httpd

# use an alternate default index file
go-httpd -index index.htm

# disable the index file
go-httpd -index=
```
