# Authentication without Authentication
A demo of a strong authentication solution that does not require any user interaction.
This is part of a talk I did at AppSec California 2018 - you can find the slide deck [here](https://www.slideshare.net/SolutoTLV/authentication-without-authentication-appsec-california).
You can read more about the solution in this [blog post](https://blog.solutotlv.com/userless-mobile-authentication/?utm_source=github).

## Running the demo
Use `docker-compose` to run the services using:
```
docker-compose up --build -d
```
And than run the ruby client using:
```
ruby client/client.rb
```

## Technical Details
The demo has 3 parts:
* Client
* Authorization Server
* Sensitive API

Both APIs are deployed using `docker-compose`, which also take care of networking, and forwarding the relevant ports to localhost.
Take a look at the `docker-file` to get a better understanding of what's going on.

### Client
The client is a small Ruby script, the demonstrate how the flow works:
* Registration with Authorization Server
* Requesting a token from the Authorization Server
* Using the token to execute an authenticated request to Sensitive API

### Authorization Server
The Authorization Server is a simple deployment of [IdentityServer4](https://identityserver.io/).
To implement our protocol, I used a custom grant (this is the only changed from what described in the blog post).
This is pretty easy to do with IdentityServer (refer to the [docs](https://identityserver4.readthedocs.io/en/release/topics/extension_grants.html) for more details).
All the relevant code is under `authorization-server/Config/JwtOTPGrantValidator`, most of the other code is wiring.

## Sensitive API
Total fake API, used to simulate client authentication. 
The API is built using .NET Core 2, ASP.Net MVC.
It has one controller (`sensitive-api/Controllers/SensitiveController`), which take the authenticated device id from the token and return it.
The server validates the token using IdentityServer middleware ([docs](https://identityserver4.readthedocs.io/en/release/topics/apis.html)).
The relevant configuration is on the Startup class (`sensitve-api/Startup.cs`).
