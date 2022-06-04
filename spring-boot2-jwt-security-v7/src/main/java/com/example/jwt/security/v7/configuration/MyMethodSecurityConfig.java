package com.example.jwt.security.v7.configuration;

import com.example.jwt.security.v7.security.MyDefaultMethodSecurityExpressionHandler;
import com.example.jwt.security.v7.security.MyPermissionEvaluator;
import com.example.jwt.security.v7.security.MyPrePostAnnotationSecurityMetadataSource;
import com.example.jwt.security.v7.service.SecurityCheckService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.expression.method.ExpressionBasedAnnotationAttributeFactory;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

import java.util.List;

/**
 * <pre>
 * Base Configuration for enabling global method security.
 * Classes may extend this class to customize the defaults,
 * but must be sure to specify the {@link EnableGlobalMethodSecurity} annotation on the subclass.
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
        final AccessDecisionManager accessDecisionManager = super.accessDecisionManager();
        LOGGER.info("get accessDecisionManager {} from : {}", accessDecisionManager.getClass().getName(), this.getClass().getSimpleName());
        if (accessDecisionManager instanceof AffirmativeBased) {
            AffirmativeBased affirmativeBased = (AffirmativeBased) accessDecisionManager;
            final List<AccessDecisionVoter<?>> decisionVoters = affirmativeBased.getDecisionVoters();
            RoleVoter roleVoter = new RoleVoter();
            roleVoter.setRolePrefix("");
            decisionVoters.add(roleVoter);
        }
        return accessDecisionManager;
    }

    @Override
    public MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
        LOGGER.info("add metadata source for {}", SecurityCheckService.class);
        ExpressionBasedAnnotationAttributeFactory attributeFactory =
            new ExpressionBasedAnnotationAttributeFactory(super.getExpressionHandler());
        MyPrePostAnnotationSecurityMetadataSource metadataSource = new MyPrePostAnnotationSecurityMetadataSource(attributeFactory);
        // metadataSource.addSecureMethod(SecurityCheckService.class, "customMethodSecurityMetadataSource", SecurityConfig.createList("ROLE_ADMIN"));
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
