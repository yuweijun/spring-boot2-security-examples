package com.example.jwt.security.v7.security;

import com.example.jwt.security.v7.service.JwtParserService;
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
        LOGGER.info("registerBeanDefinitions by ImportBeanDefinitionRegistrar : {}", this.getClass().getPackage().getName());
        for (String annotationTypeName : importingClassMetadata.getAnnotationTypes()) {
            LOGGER.info("annotationTypeName : {}", annotationTypeName);
        }
        BeanDefinition beanDefinition = new RootBeanDefinition();
        beanDefinition.setBeanClassName(JwtParserService.class.getName());
        registry.registerBeanDefinition("jwtParserService", beanDefinition);
    }

}
