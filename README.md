# ultra

## Description

ultra - Beyond HTTP

## Usage

```
# serve files from the current directory via http://localhost:8080/
ultra

# serve files via http://hostname:5000/
ultra -http :5000

# set the bind address via environment variables
HTTP_BIND=:5000 ultra

# use an alternate default index file
ultra -index index.htm

# disable the index file
ultra -index=
```
