package com.example.jwt.security.v2.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.type.AnnotationMetadata;

public class JwtSecurityImportBeanDefinitionRegistrar implements ImportBeanDefinitionRegistrar {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtSecurityImportBeanDefinitionRegistrar.class);

    @Override
    public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry) {
        LOGGER.info("registerBeanDefinitions by ImportBeanDefinitionRegistrar");
        for (String annotationTypeName : importingClassMetadata.getAnnotationTypes()) {
            LOGGER.info("annotationTypeName : {}", annotationTypeName);
        }
        BeanDefinition beanDefinition = new RootBeanDefinition();
        beanDefinition.setBeanClassName("com.example.jwt.security.v2.service.JwtParserService");
        registry.registerBeanDefinition("jwtParserService", beanDefinition);
    }

}
