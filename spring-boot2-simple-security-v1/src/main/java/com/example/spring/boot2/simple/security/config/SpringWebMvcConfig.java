package com.example.spring.boot2.simple.security.config;

import com.example.spring.boot2.simple.security.web.FilterChainProxy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

public class SpringWebMvcConfig implements WebMvcConfigurer {

    private static final Logger LOGGER = LoggerFactory.getLogger(SpringWebMvcConfig.class);

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("home");
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/static/**").addResourceLocations("classpath:/static/");
    }

    @Bean
    public FilterRegistrationBean<FilterChainProxy> filterChainProxy() {
        LOGGER.info("config filter bean : filterChainProxy");
        FilterRegistrationBean<FilterChainProxy> bean = new FilterRegistrationBean<>();
        bean.setFilter(new FilterChainProxy());
        bean.setName("filterChainProxy");
        bean.addUrlPatterns("/*");
        bean.setOrder(21);
        return bean;
    }
}
