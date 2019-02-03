# Spring Security JWT Auth

Java application using Spring Framework to perform authentication and authorization of users in a demo API.
A JWT token is returned to the user after a successful login and this token must be sent on every request to authorize the user to access the API.
The project uses Spring Security and it has two security chains setup, one for JWT authentication/authorization and another one for Basic authentication.

Run command:
```
mvnw spring-boot:run
```

## Routes
* POST /api/login
  * Send credentials and get a JWT token on response Authorization header 
  * Valid users: user1, user2, admin / Password: 12345
  * Example request body: { "login": "user1", "password": "12345" }
  
* GET /api/basic/welcome
  * Send Basic authorization to access
  * Username: user1 / Password: 12345
  
* GET /api/welcome
  * Send Bearer authorization with JWT token to access.
 
* GET /api/admin/welcome
  * Send Bearer authorization with Admin JWT token to access.

## What I Learned
* Spring Security configuration
  * Filters
  * Multiple chain configuration
  * Request authorization
  * Custom authentication provider
* JWT generation and validation
* Code generation with Lombok