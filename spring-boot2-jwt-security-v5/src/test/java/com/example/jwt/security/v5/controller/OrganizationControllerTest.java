package com.example.jwt.security.v5.controller;

import com.example.jwt.security.v5.JwtSecurityV5Application;
import com.example.jwt.security.v5.model.Organization;
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
@SpringBootTest(classes = {JwtSecurityV5Application.class}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class OrganizationControllerTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserControllerTest.class);

    @LocalServerPort
    private int port;

    @Before
    public void setup() {
        LOGGER.info("server port is {}", port);
        RestAssured.port = port;
    }

    @Test
    public void findOrganization_byAdmin_thenOK() {
        Organization organization = givenAuth("admin", "admin")
            .contentType(MediaType.APPLICATION_JSON_VALUE)
            .when()
            .get("/organizations/1")
            .prettyPeek()
            .then()
            .statusCode(HttpStatus.OK.value())
            .extract().as(Organization.class);
        assertTrue(organization.getId() == 1);
    }

    @Test
    public void findOrganization_byClient_thenForbidden() {
        Response response = givenAuth("client", "client").get("/organizations/2");
        response.prettyPeek();
        assertEquals(403, response.getStatusCode());
    }

    private RequestSpecification givenAuth(String username, String password) {
        FormAuthConfig formAuthConfig = new FormAuthConfig("/login", "username", "password");
        return RestAssured.given().auth().form(username, password, formAuthConfig);
    }
}