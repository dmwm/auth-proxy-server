Here we provide a recipe for nginx gRPC proxy server. We'll use the following
setup:

```
nginx -> auth proxy server -> gRPC backend
```

Therefore, we'll need the following components:
- [auth proxy server](https://github.com/dmwm/auth-proxy-server) (APS)
You'll need to compile the code and start APS with proper configuration. It
should include the ingress path to `/token` end-point, e.g.
```
   "ingress": [
        ....
        {"path":"/token", "service_url":"http://localhost:8443"}
    ],
```
This end-point will later used by nginx auth step, see below

- [nginx server](https://nginx.org/en/download.html), download it and compile
with the following options:
```
./configure --with-http_ssl_module --with-http_v2_module --with-http_auth_request_module
```

- nginx configuration (we'll call it `grpc.conf`):
```
events {}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent"';

    server {
        listen 1443 http2 ssl;
        ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers         HIGH:!aNULL:!MD5;

        ssl_certificate     /Users/vk/certificates/self/mydomain.com.crt;
        ssl_certificate_key /Users/vk/certificates/self/mydomain.com.key;

        access_log logs/access.log main;


        # https://developers.shopware.com/blog/2015/03/02/sso-with-nginx-authrequest-module/
        # https://developer.okta.com/blog/2018/08/28/nginx-auth-request
        # Any request to this server will first be sent to this URL
        auth_request /auth;

        location = /auth {
          # This address is where APS will be listening on
          proxy_pass https://127.0.0.1:8443/token;
          proxy_pass_request_body off; # no need to send the POST body
          proxy_pass_request_headers on;

          proxy_set_header Content-Length "";
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto $scheme;
          proxy_set_header X-Original-URI $request_uri;
          proxy_set_header Host $http_host;

          # these return values are passed to the @error401 call
          auth_request_set $auth_resp_jwt $upstream_http_x_vouch_jwt;
          auth_request_set $auth_resp_err $upstream_http_x_vouch_err;
          auth_request_set $auth_resp_failcount $upstream_http_x_vouch_failcount;
        }

        error_page 401 = @error401;

        # If the user is not logged in, redirect them to login URL
        # Please adjust return url (here we used cmsweb-auth as an example)
        location @error401 {
          return 302 https://cmsweb-auth.cern.ch/token?url=https://$http_host$request_uri&vouch-failcount=$auth_resp_failcount&X-Vouch-Token=$auth_resp_jwt&error=$auth_resp_err;
        }

        location / {
            # Replace localhost:9999 with the address and port of your gRPC server
            # The 'grpc://' prefix is optional; unencrypted gRPC is the default
            grpc_pass grpc://localhost:9999;
        }
    }
}

```

- run nginx server as following:
```
# replace location of error.log and prefix accordingly to your setup
objs/nginx -e /tmp/nginx/error.log -p /tmp/nginx -c $PWD/grpc.conf
```

With this setup you can run gRPC client with OAuth token and the request
will first routed to APS for authentication, then (if APS returns 200 OK),
will be redirected to grpc backend server (in our example above it runs on
localhost port 9999).
