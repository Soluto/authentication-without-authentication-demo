# A demo of seamless authentication solution
A small demo of the solution for a talk on AppSec Israel I did.
You can read more about the solution in this [blog post](https://blog.solutotlv.com/userless-mobile-authentication/?utm_source=github).

## Running the demo
Use `docker-compose` to run the services using:
```
docker-compose up --build -d
```
And than run the ruby client using:
```
ruby client\client.rb
```