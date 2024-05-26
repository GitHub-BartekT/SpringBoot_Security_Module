# Spring Security Module
### Overview
The module covers all basic authorization and authentication features.

## Scope of the project

### Live demo in postman

https://youtu.be/LfLcWpJ4oq4

![img_1.png](img_1.png)

### Major features:
- Registration with:
  - Token confirmation
  - Email confirmation
- Login 
- Tokens:
  - Register
  - Refresh
  - Access
- Token refreshing
- User updating
- User deleting

## API💡
Access the API documentation at:http://localhost:8080/swagger-ui/index.html#/

![img.png](img.png)

 ## Tech ✅
- Java
- SpringBoot
  - Spring Security
  - Spring Mail
  - Spring JPA
- Hibernate
- PostegreSQL
- Swagger
- Lombok
- Postman

## Run🚀

1. Database 
   1. Create a database named "auth" in PostgreSQL.
   2. Create a .env file with your PostgreSQL credentials in the root project directory:
```makefile
POSTGRES_USER=
POSTGRES_PASSWORD=
```
2. Instal and run maildev to receive mails
- ```npm install -g maildev```
- ```maildev```

You can check emails at:
```java
http://127.0.0.1:1080/
```
3. Run project
- ```mvn spring-boot:run ```

## My Linkedin:
https://www.linkedin.com/in/bartlomiejtucholski/


 
