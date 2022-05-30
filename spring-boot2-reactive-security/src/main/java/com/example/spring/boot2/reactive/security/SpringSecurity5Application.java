package com.example.spring.boot2.reactive.security;

import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.web.reactive.config.EnableWebFlux;

@EnableWebFlux
public class SpringSecurity5Application {

    public static void main(String[] args) {
        new AnnotationConfigApplicationContext(SpringSecurity5Application.class);
    }

}
