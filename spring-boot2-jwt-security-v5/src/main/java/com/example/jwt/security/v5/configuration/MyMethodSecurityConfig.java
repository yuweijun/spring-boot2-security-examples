package com.example.jwt.security.v5.configuration;

import com.example.jwt.security.v5.security.MyDefaultMethodSecurityExpressionHandler;
import com.example.jwt.security.v5.security.MyPermissionEvaluator;
import com.example.jwt.security.v5.service.SecurityCheckService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
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
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class MyMethodSecurityConfig extends GlobalMethodSecurityConfiguration {

    private static final Logger LOGGER = LoggerFactory.getLogger(MyMethodSecurityConfig.class);

    @Autowired
    private ApplicationContext applicationContext;

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

    /**
     * <pre>
     * There was an unexpected error (type=Bad Request, status=400).
     * Something went wrong
     * java.lang.IllegalArgumentException:
     *      Failed to evaluate expression '@permissionCheckService.hasPermission(#message, 'write')'
     * Caused by: org.springframework.expression.spel.SpelEvaluationException: EL1057E: No bean resolver registered in the context to resolve access to bean 'permissionCheckService'
     *      at org.springframework.expression.spel.ast.BeanReference.getValueInternal(BeanReference.java:51)
     *      at org.springframework.expression.spel.ast.CompoundExpression.getValueRef(CompoundExpression.java:55)
     *      at org.springframework.expression.spel.ast.CompoundExpression.getValueInternal(CompoundExpression.java:91)
     *      at org.springframework.expression.spel.ast.SpelNodeImpl.getTypedValue(SpelNodeImpl.java:117)
     *      at org.springframework.expression.spel.standard.SpelExpression.getValue(SpelExpression.java:308)
     *      at org.springframework.security.access.expression.ExpressionUtils.evaluateAsBoolean(ExpressionUtils.java:26)
     * </pre>
     * You need to ensure that you set the ApplicationContext on the DefaultMethodSecurityExpressionHandler.
     */
    @Override
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        LOGGER.info("MyMethodSecurityConfig#createExpressionHandler from class : {}", this.getClass().getName());
        MyDefaultMethodSecurityExpressionHandler expressionHandler = new MyDefaultMethodSecurityExpressionHandler();
        expressionHandler.setPermissionEvaluator(new MyPermissionEvaluator());
        expressionHandler.setApplicationContext(applicationContext);
        return expressionHandler;
    }

}
