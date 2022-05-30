package com.example.jwt.security.v1.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

@Retention(value = java.lang.annotation.RetentionPolicy.RUNTIME)
@Target(value = {java.lang.annotation.ElementType.TYPE})
@Documented
@Import({JwtSecurityImportBeanDefinitionRegistrar.class, WebSecurityConfig.class, SpringWebMvcConfig.class})
@Configuration
public @interface EnableJwtSecurity {

}

