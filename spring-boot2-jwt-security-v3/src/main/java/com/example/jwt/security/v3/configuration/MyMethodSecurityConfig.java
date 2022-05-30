package com.example.jwt.security.v3.configuration;

import com.example.jwt.security.v3.service.SecurityCheckService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

/**
 * <pre>
 * disable annotation @EnableGlobalMethodSecurity in class {@link MultiHttpSecurityConfig.WebAdminSecurityConfig} avoid error:
 * The bean 'methodSecurityInterceptor', defined in class path resource [org/springframework/security/config/annotation/method/configuration/GlobalMethodSecurityConfiguration.class], could not be registered. A bean with that name has already been defined in class path resource [com/example/jwt/security/v3/configuration/MyMethodSecurityFirstConfig.class] and overriding is disabled.
 *
 * Base Configuration for enabling global method security.
 * Classes may extend this class to customize the defaults,
 * but must be sure to specify the EnableGlobalMethodSecurity annotation on the subclass.
 * </pre>
 */
@Configuration
@Order(80)
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class MyMethodSecurityConfig extends GlobalMethodSecurityConfiguration {

    private static final Logger LOGGER = LoggerFactory.getLogger(MyMethodSecurityConfig.class);

    @Override
    protected AccessDecisionManager accessDecisionManager() {
        LOGGER.info("get accessDecisionManager from : {}", this.getClass().getSimpleName());
        return super.accessDecisionManager();
    }

    @Override
    public MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
        LOGGER.info("add metadata source for {}", SecurityCheckService.class);
        MapBasedMethodSecurityMetadataSource metadataSource = new MapBasedMethodSecurityMetadataSource();
        metadataSource.addSecureMethod(SecurityCheckService.class, "customMethodSecurityMetadataSource", SecurityConfig.createList("ROLE_ADMIN"));
        return metadataSource;
    }
}
