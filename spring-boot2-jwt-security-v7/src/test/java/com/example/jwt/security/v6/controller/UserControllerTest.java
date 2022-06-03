package com.example.jwt.security.v6.controller;

import com.example.jwt.security.v7.JwtSecurityV7Application;
import com.example.jwt.security.v7.model.User;
import com.jayway.restassured.RestAssured;
import com.jayway.restassured.authentication.FormAuthConfig;
import com.jayway.restassured.response.Response;
import com.jayway.restassured.specification.RequestSpecification;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {JwtSecurityV7Application.class}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class UserControllerTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserControllerTest.class);

    @LocalServerPort
    private int port;

    @Before
    public void setup() {
        LOGGER.info("server port is {}", port);
        RestAssured.port = port;
    }

    @Test
    public void whenGetUserById_thenOK() {
        User user = givenAuth("admin", "admin")
            .contentType(MediaType.APPLICATION_JSON_VALUE)
            .when()
            .get("/users/find/1")
            .prettyPeek()
            .then()
            .statusCode(HttpStatus.OK.value())
            .extract().as(User.class);

        assertTrue(user.getId() == 1);
    }

    @Test
    public void whenPostByClient_thenForbidden() {
        givenAuth("client", "client")
            .contentType(MediaType.APPLICATION_JSON_VALUE)
            .body(createUser(98))
            .when()
            .post("/users/create")
            .prettyPeek()
            .then()
            .statusCode(HttpStatus.FORBIDDEN.value());
    }

    @Test
    public void whenPostByUser_thenOk() {
        Response response = givenAuth("user", "user")
            .contentType(MediaType.APPLICATION_JSON_VALUE)
            .body(createUser(99))
            .post("/users/create");
        assertEquals(201, response.getStatusCode());
        assertTrue(response.asString().contains("id"));
    }

    @Test
    public void whenPostByAdmin_thenOk() {
        Response response = givenAuth("admin", "admin")
            .contentType(MediaType.APPLICATION_JSON_VALUE)
            .body(createUser(100))
            .post("/users/create");
        assertEquals(201, response.getStatusCode());
        assertTrue(response.asString().contains("id"));
    }

    private User createUser(int postfix) {
        User user2 = new User();
        user2.setUsername("user_" + postfix);
        user2.setPassword("user_" + postfix);
        return user2;
    }

    private RequestSpecification givenAuth(String username, String password) {
        FormAuthConfig formAuthConfig = new FormAuthConfig("/login", "username", "password");
        return RestAssured.given().auth().form(username, password, formAuthConfig);
    }
}