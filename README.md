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
* Testing
  * Spring and JUnit 5 integration
  * JUnit 5 assertions
  * Parameterized tests
  * Mocking with Mockito
  * Assertions with AssertJ
  
## Recommendations
* Multiple Entry Points in Spring Security
https://www.baeldung.com/spring-security-multiple-entry-points

* Architecture Deep Dive in Spring Security - Joe Grandja @ Spring I/O 2017
https://www.youtube.com/watch?v=8rnOsF3RVQc

* Spring Security Reference
https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/

* Unit and Integration Tests for RestControllers in Spring Boot
https://thepracticaldeveloper.com/2017/07/31/guide-spring-boot-controller-tests/

* JUnit 5 – Parameterized Tests
https://blog.codefx.org/libraries/junit-5-parameterized-tests/