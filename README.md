# weakJWTlib - Vulnerable JWT application

## What is this about?

The goal of this small project is to provide an application (an API endpoint to be precise, no nice GUIs to play with) vulnerable to multiple known JWT weaknesses.

## What is JWT?

JSON Web Tokens (JWT) are widely used for access control purposes in many web or API-based applications.
Most usage of JWTs include: 
* Using the JWT directly as a bearer token - authorization claims
* Using the JWT in a more complex authorization framework such as OAuth2.0 (JWT bearer tokens) or OpenID
* Information exchange - Integrity sensitive information

JWTs are extensively covered on the web. A few resources I would recommend to learn more:
* Online tool to play with JWTs and learn - https://jwt.io/introduction/
* RFC on JWT tokens - RFC7519 - https://tools.ietf.org/html/rfc7519
* RFC on JWT best-practices - RFC8725 - https://tools.ietf.org/html/rfc8725
* Auth0 - https://auth0.com/docs/tokens/json-web-tokens

JWTs are in fact either (1) signed, in which case it becomes a JSON Web Signature (JWS) or (ii) encrypted, a JSON Web Encryption (JWE). You can see JWT as an abstractions of JWS/JWE. 
A nicely written article introducing the concepts can be found on Medium: https://medium.facilelogin.com/jwt-jws-and-jwe-for-not-so-dummies-b63310d201a3

## What security concerns is there with JWTs?

Being widely spread, and used in critical flows (authorization, data exchange...), JWT libraries have flourished over the years and languages.
With that however came a few interesting vulnerabilities, common to most of the original versions of these libraries.
These vulnerabilities were due to either bad development practices or confusion in the RFC interpretation/implementation.
Litterature already exist on these vulnerabilities and how they can be exploited:
* NCC - https://www.nccgroup.com/uk/about-us/newsroom-and-events/blogs/2019/january/jwt-attack-walk-through/
* Pragmatic Security - https://pragmaticwebsecurity.com/articles/apisecurity/hard-parts-of-jwt.html
* Auth0 - https://auth0.com/docs/tokens/json-web-tokens

## So, what is the point?

The idea was not to re-do yet another article on these vulnerabilties, which are anyway fixed on latest versions of the most commonly used libraries. No, instead, the idea was to understand how these vulnerablities happened, and how they could be exploited. 
This python application is using latest version of a JWT library, for which the goal was to make it vulnerable again and offer a playground to understand and test these vulnerablities.

## Great, but where do I start?


## Ok it is running and then what? Where are the darn vulnerabilities?


## Ok but I am lazy, I want to see the solution


## What is next?

* Imporving the code (cleaning) and making the application a bit more realistic (a small bit): products, orders, details, users instead of just users.
* Adding OAuth2.0 and making it vulnerable to knwon OAuth2.0 vulnerabilities
* Adding OpenID and making it vulnerable again

## Why?

Learning, playing, sharing!
