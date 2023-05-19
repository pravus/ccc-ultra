# ccc-ultra

## Overview

ccc-ultra - A simple HTTP service for serving files from the current directory tree.

## Usage

```
# serve files from the current directory via http://localhost:8080/
ccc-ultra

# serve files via http://hostname:5000/
ccc-ultra -http :5000

# set the bind address via environment variables
HTTP_BIND=:5000 ccc-ultra

# use an alternate default index file
ccc-ultra -index index.htm

# disable the index file
ccc-ultra -index=
```
