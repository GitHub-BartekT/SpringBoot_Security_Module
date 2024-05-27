# Spring Security Module
### Overview
The module covers all basic authorization and authentication features.

## Scope of the project

### Live demo in postman

https://www.youtube.com/watch?v=INOvOtW8JO8

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

### Fast launch
- ```docker-compose down -v```
- ```maildev```
- ```mvn spring-boot:run ```

### Launch
Each taks in deferent terminals
1. Database docker image
- ``` docker-compose down -v```

You can check database on:

```java
http://localhost:5000/
```
With credentials:

| Rodzaj bazy | PostgreSQL |
|-------------|------------|
| Serwer      | db         |
| Użytkownik  | postgres   |
| Hasło       | pass       |
| Baza danych | auth       |


```java
http://localhost:5000/
```

2. Instal and run maildev to receive e-mails

- ```npm install -g maildev``` - instal
- ```maildev``` - run


```java
http://127.0.0.1:1080/
```
3. Run project
- ```mvn spring-boot:run ```

## My Linkedin:
https://www.linkedin.com/in/bartlomiejtucholski/


 
