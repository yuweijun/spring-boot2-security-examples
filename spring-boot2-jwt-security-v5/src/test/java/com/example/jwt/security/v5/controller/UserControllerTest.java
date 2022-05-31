package com.example.jwt.security.v5.controller;

import com.example.jwt.security.v5.JwtSecurityV5Application;
import com.example.jwt.security.v5.model.User;
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

    /**
     * BasicErrorController#getErrorAttributes()
     * ...
     * getErrorAttributes:110, DefaultErrorAttributes (org.springframework.boot.web.servlet.error)
     * getErrorAttributes:89, AbstractErrorController (org.springframework.boot.autoconfigure.web.servlet.error)
     * error:105, BasicErrorController (org.springframework.boot.autoconfigure.web.servlet.error)
     * invoke0:-1, NativeMethodAccessorImpl (jdk.internal.reflect)
     * invoke:62, NativeMethodAccessorImpl (jdk.internal.reflect)
     * invoke:43, DelegatingMethodAccessorImpl (jdk.internal.reflect)
     * invoke:566, Method (java.lang.reflect)
     * doInvoke:190, InvocableHandlerMethod (org.springframework.web.method.support)
     * invokeForRequest:138, InvocableHandlerMethod (org.springframework.web.method.support)
     * invokeAndHandle:105, ServletInvocableHandlerMethod (org.springframework.web.servlet.mvc.method.annotation)
     * invokeHandlerMethod:878, RequestMappingHandlerAdapter (org.springframework.web.servlet.mvc.method.annotation)
     * handleInternal:792, RequestMappingHandlerAdapter (org.springframework.web.servlet.mvc.method.annotation)
     * handle:87, AbstractHandlerMethodAdapter (org.springframework.web.servlet.mvc.method)
     * doDispatch:1040, DispatcherServlet (org.springframework.web.servlet)
     * doService:943, DispatcherServlet (org.springframework.web.servlet)
     * processRequest:1006, FrameworkServlet (org.springframework.web.servlet)
     * doPost:909, FrameworkServlet (org.springframework.web.servlet)
     * service:652, HttpServlet (javax.servlet.http)
     * service:883, FrameworkServlet (org.springframework.web.servlet)
     * service:733, HttpServlet (javax.servlet.http)
     * internalDoFilter:231, ApplicationFilterChain (org.apache.catalina.core)
     * doFilter:166, ApplicationFilterChain (org.apache.catalina.core)
     * doFilter:320, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * invoke:115, FilterSecurityInterceptor (org.springframework.security.web.access.intercept)
     * doFilter:90, FilterSecurityInterceptor (org.springframework.security.web.access.intercept)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * invoke:115, FilterSecurityInterceptor (org.springframework.security.web.access.intercept)
     * invoke:42, MyFilterSecurityInterceptor (com.example.jwt.security.v5.security)
     * doFilter:66, MyFilterSecurityInterceptor (com.example.jwt.security.v5.security)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilter:118, ExceptionTranslationFilter (org.springframework.security.web.access)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilter:84, SessionManagementFilter (org.springframework.security.web.session)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilter:111, AnonymousAuthenticationFilter (org.springframework.security.web.authentication)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilter:158, SecurityContextHolderAwareRequestFilter (org.springframework.security.web.servletapi)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilter:63, RequestCacheAwareFilter (org.springframework.security.web.savedrequest)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilter:103, OncePerRequestFilter (org.springframework.web.filter)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilter:103, OncePerRequestFilter (org.springframework.web.filter)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilter:216, DefaultLoginPageGeneratingFilter (org.springframework.security.web.authentication.ui)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilter:200, AbstractAuthenticationProcessingFilter (org.springframework.security.web.authentication)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilter:200, AbstractAuthenticationProcessingFilter (org.springframework.security.web.authentication)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilter:116, LogoutFilter (org.springframework.security.web.authentication.logout)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilter:24, MyFilter (com.example.jwt.security.v5.security)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilter:103, OncePerRequestFilter (org.springframework.web.filter)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilter:105, SecurityContextPersistenceFilter (org.springframework.security.web.context)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilter:103, OncePerRequestFilter (org.springframework.web.filter)
     * doFilter:334, FilterChainProxy$VirtualFilterChain (org.springframework.security.web)
     * doFilterInternal:215, FilterChainProxy (org.springframework.security.web)
     * doFilter:178, FilterChainProxy (org.springframework.security.web)
     * invokeDelegate:358, DelegatingFilterProxy (org.springframework.web.filter)
     * doFilter:271, DelegatingFilterProxy (org.springframework.web.filter)
     * internalDoFilter:193, ApplicationFilterChain (org.apache.catalina.core)
     * doFilter:166, ApplicationFilterChain (org.apache.catalina.core)
     * doFilterInternal:100, RequestContextFilter (org.springframework.web.filter)
     * doFilter:119, OncePerRequestFilter (org.springframework.web.filter)
     * internalDoFilter:193, ApplicationFilterChain (org.apache.catalina.core)
     * doFilter:166, ApplicationFilterChain (org.apache.catalina.core)
     * doFilter:103, OncePerRequestFilter (org.springframework.web.filter)
     * internalDoFilter:193, ApplicationFilterChain (org.apache.catalina.core)
     * doFilter:166, ApplicationFilterChain (org.apache.catalina.core)
     * doFilter:103, OncePerRequestFilter (org.springframework.web.filter)
     * internalDoFilter:193, ApplicationFilterChain (org.apache.catalina.core)
     * doFilter:166, ApplicationFilterChain (org.apache.catalina.core)
     * invoke:712, ApplicationDispatcher (org.apache.catalina.core)
     * processRequest:461, ApplicationDispatcher (org.apache.catalina.core)
     * doForward:384, ApplicationDispatcher (org.apache.catalina.core)
     * forward:312, ApplicationDispatcher (org.apache.catalina.core)
     * ...
     * run:829, Thread (java.lang)
     */
    @Test
    public void whenPostByClient_thenForbidden() {
        givenAuth("client", "client")
            .contentType(MediaType.APPLICATION_JSON_VALUE)
            .body(createUser(98))
            .when()
            .post("/users/create")
            .prettyPeek() // DefaultErrorAttributes
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