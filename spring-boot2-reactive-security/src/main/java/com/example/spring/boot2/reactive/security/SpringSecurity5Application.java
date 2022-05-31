package com.example.spring.boot2.reactive.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.reactive.config.EnableWebFlux;

@EnableWebFlux
@SpringBootApplication
public class SpringSecurity5Application {

    public static void main(String[] args) {
        // new AnnotationConfigApplicationContext(SpringSecurity5Application.class);
        SpringApplication.run(SpringSecurity5Application.class, args);
    }

}
