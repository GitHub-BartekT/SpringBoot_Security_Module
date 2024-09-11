# Spring Security Module - EN
### Overview
This project focuses on implementing advanced authorization and authentication features using **Spring Boot 3**.

## Scope of the project

### Live demo in postman

📺[Watch the demo on YouTube](https://www.youtube.com/watch?v=INOvOtW8JO8)📺

The demo video covers the major functionalities of the project, including user registration, login, token handling, and more.

### Showcase

![img_1.png](img_1.png)

### Major Features:
- **User Registration:**
  - Email confirmation with token-based validation.
- **User Login:**
  - Authentication using user credentials.
- **Token Management:**
  - **Registration Token:** Used to confirm user registration.
  - **Refresh Token:** Used to generate new access tokens.
  - **Access Token:** Used to authenticate and access protected endpoints.
  - **Delete Token:** Used to confirm account deletion.
- **Token Refreshing:** Automatic token refresh before expiration.
- **User Management:**
  - Updating user details.
  - Deleting users with confirmation tokens.

## API💡
The API documentation is available via **Swagger UI**:
[Swagger UI](http://localhost:8080/swagger-ui/index.html#/)

![Endpoints.png](..%2FEndpoints.png)

## Tech Stack ✅
- **Java**
- **Spring Boot**
  - Spring Security
  - Spring Mail
  - Spring JPA
- **Tests**
  - Integration Testing
  - Test Containers
  - JUnit
- **Hibernate**
- **PostgreSQL**
- **Swagger**
- **Lombok**
- **Postman**
- **MailDev**
- **Docker**

## Modules

![Modules.png](..%2FModules.png)

## Potential Improvements 🚀

- **Google Registration - OAuth2:** Implement Google OAuth2 login.
- **Advanced Token Management:** Implement token invalidation and blacklisting.
- **Device Management:** Add device tracking and login notifications for new devices.

## Run instructions🚀

### Fast launch🚀

- ```docker-compose up -d```
- ```maildev```
- ```mvn spring-boot:run ```

### Integration test🚀

- ```mvn test ```

### Launch🚀

Each task need a different terminal:
1. Database docker image
- ``` docker-compose up -d```

2. Install and run MailDev to receive emails:

- ```npm install -g maildev``` - install
- ```maildev``` - run

Access MailDev at:

```java
http://127.0.0.1:1080/
```

3. Run the project
- ```mvn spring-boot:run ```

## My Linkedin:
https://www.linkedin.com/in/bartlomiejtucholski/


 
