The `decode-token` client is a simple tool to decode given token.

```
# build client
go build

# run client
./decode-token -token=$token

# if token is invalid you'll see the following message:
2022/02/22 13:49:38 The token is not valid
# otherwise the token attributes will be printed like this:

{
    "sub": "xxxx-yyyy-6251d28e94a1",
    "aud": "[https://wlcg.cern.ch/jwt/v1/any]",
    "iss": "https://cms-auth.web.cern.ch/",
    "username": "",
    "active": true,
    "session_state": "",
    "clientId": "xxxx-yyyy-51ee6a978680",
    "email": "",
    "scope": "address phone openid offline_access profile eduperson_scoped_affiliation eduperson_entitlement email wlcg",
    "exp": 1645557402,
    "clientHost": ""
}

```
