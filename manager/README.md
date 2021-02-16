# Token manager
This area contains code to manage tokens provided by auth proxy server.
```
# build token manager
make

# run token manager with given URL and valid TOKEN
# it will obtain new token at given interval and write it out
# to given file (/tmp/token). The written token will be access token
# and during renewal process it will use refresh token
./token -interval 600 -out /tmp/token -url <URL> -token <token>
```
