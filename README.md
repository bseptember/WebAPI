# WebAPI

## Description
A web API that a client uses to do the following:
1. Retrieve an OAuth access/refresh token issued by an identity server for further access to the web API.
2. Retrieve user information stored in an identity server.
3. Retrieve/store database info.

## Prerequisites

1. MS Visual Studio


## Start

1. Change the IP address to your local IP Address in the following files: appsettings.json, appsettings.Development.json, launchSettings.json

2. Use the Registration-system project as a quick start to run the required docker containers and use the generated root_ca.crt.

3. Run certmgr.msc on windows run, import the generated root_ca.crt.

4. Run your project.


## Flow Test

WebAPI endpoint = <your-ip>:5053/_keycloak/version

1. Webapi generates verifier, uses it to generate code challenge.

2. Cheks if token is available or valid, if so, print to screen.

3. Invalid will go to a different enpoint on the webapi, i.e. /_keycloak/login

4. Using the challenge and redirect uri this endpoint creates a body to send to the Oauth endpoint.

5. The Oauth provider will then return the auth code to the provided endpoint on the previous step.

6. The callback (redirect uri) then creates a body using the received auth code to request the token from the Oauth provider.

7. Once the token is received, it can be used in the Header of any Oauth endpoint to request data.

8. The token can also be used to on the webapi to verifier if the user is allowed to retrieve data from the database, but additional checks need to be put in place.


## Usage for keycloak

To implement PKCE (needs to be enabled in the identity server) and get redirected to the identity server's log-in page via the web API:
```
1. On log-in request, create a code verifier by generating a random number using the following from the Functions Class:

GenerateCodeVerifier()

2. Create a code challenge by hashing the code verifier using the following from the Functions Class:
GenerateCodeChallenge()


3. Post Request containing the code challenge and the redirect uri the app is redirected to on successful log-in
(HttpPost)
https://{web api address}:/<auth-provider>/login
(Request Body)
{
    "uri" : "abc",
    "challenge" : "def"
}

The code challenge is stored in the identity server and will be used to verify a code verifier later on in the process. 
```

To retrieve an access token from the identity server, with PKCE enabled, via the web API:
```
(HttpPost)
https://{web api address}:/<auth-provider>/accesstoken
(Request Body)
{
    "uri" : "abc",
    "verifier" : "def",
    "code" : "ghi"
}

(Sample Response)
{
    "access_token": "eyJ...",
    "expires_in": 3599,
    "refresh_token": "mwYz7GJN-LAFNN6KOh5QcNcIvLMEQfwmlYnEcpduESfq4_KGOKlVOQ",
    "refresh_token_id": "12768d82-505f-4be2-8eab-54d2b7c38356",
    "token_type": "Bearer",
    "userId": "f4a9f5ff-5824-4d7d-bdcc-ecdc91e8314b"
}

* note that the code verifier ("verifier") is hashed by the identity server and compared to the stored code challenge and only if it matches does the identity server return an access token
* note that a refresh token is only returned if the functionality is enabled in identity server
```

To retrieve an access token from the identity server using a refresh token (needs to be enabled in the identity server) via the web API:
```
(HttpGet)
https://{web api address}:/<auth-provider>/refreshtoken

Add a Cookie to the request:
refresh={access token}

(Sample Response)
{
    "access_token": "eyJ...",
    "expires_in": 3600,
    "refresh_token": "mwYz7GJN-LAFNN6KOh5QcNcIvLMEQfwmlYnEcpduESfq4_KGOKlVOQ",
    "refresh_token_id": "12768d82-505f-4be2-8eab-54d2b7c38356",
    "scope": "offline_access",
    "token_type": "Bearer",
    "userId": "f4a9f5ff-5824-4d7d-bdcc-ecdc91e8314b"
}

* note that in order to use refresh tokens, the identity server must be configured to generate refresh tokens and the parameter "&scope=offline_access" must be added to the log-in uri.

```

To retrieve user information from the identity server via the web API:
```
(HttpGet)
https://{web api address}:/<auth-provider>/userinfo
(Request Authorization Header)
{
    "type": "Bearer Token",
    "token": "eyJ..."
}

(Sample Response)
{
    "applicationId": "d93c8800-d9ea-47f3-bebf-d1b35a4acbe0",
    "birthdate": "1980-01-01",
    "email": "joe@dirt.com",
    "email_verified": true,
    "family_name": "Dirt",
    "given_name": "Joe",
    "middle_name": "",
    "name": "Joe Dirt",
    "phone_number": "0125482020",
    "preferred_username": "joe",
    "roles": [],
    "scope": "offline_access",
    "sid": "12768d82-505f-4be2-8eab-54d2b7c38356",
    "sub": "f4a9f5ff-5824-4d7d-bdcc-ecdc91e8314b",
    "tid": "6d951fd3-528d-952e-3f0c-39724a0f0770"
}
```

To log-out using oauth via the web API:
```
(HttpPost)
https://{web api address}:/auth/logout
(Request Authorization Header)
{
    "client_id": {id},
    "client_secret": {secret},
    "refresh_token:" {token}
}
(Request Body)
{
    "uri" : {redirect uri}
}
```


- Postman is a good tool for testing the web API using Http requests


## Authors and acknowledgment
BR September


## Project status
Development
