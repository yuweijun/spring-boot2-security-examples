# including MyMethodSecurityConfig and HasPermissionController

# Caused by: org.springframework.expression.spel.SpelEvaluationException: EL1057E: No bean resolver registered in the context to resolve access to bean 'permissionCheckService'

    There was an unexpected error (type=Bad Request, status=400).
    Something went wrong
    java.lang.IllegalArgumentException: 
        Failed to evaluate expression '@permissionCheckService.hasPermission(#message, 'write')'
    Caused by: org.springframework.expression.spel.SpelEvaluationException: EL1057E: No bean resolver registered in the context to resolve access to bean 'permissionCheckService'
        at org.springframework.expression.spel.ast.BeanReference.getValueInternal(BeanReference.java:51)
        at org.springframework.expression.spel.ast.CompoundExpression.getValueRef(CompoundExpression.java:55)
        at org.springframework.expression.spel.ast.CompoundExpression.getValueInternal(CompoundExpression.java:91)
        at org.springframework.expression.spel.ast.SpelNodeImpl.getTypedValue(SpelNodeImpl.java:117)
        at org.springframework.expression.spel.standard.SpelExpression.getValue(SpelExpression.java:308)
        at org.springframework.security.access.expression.ExpressionUtils.evaluateAsBoolean(ExpressionUtils.java:26)

You need to ensure that you set the ApplicationContext on the DefaultMethodSecurityExpresssionHandler. For example:

```java
@Autowired
private ApplicationContext context;

// ...

@Override
protected MethodSecurityExpressionHandler expressionHandler() {
    DefaultMethodSecurityExpressionHandler expressionHandler =
            new DefaultMethodSecurityExpressionHandler();
    expressionHandler.setPermissionEvaluator(appPermissionEvaluator());

    // !!!
    expressionHandler.setApplicationContext(context);

    return expressionHandler;
}
```

# References

1. https://stackoverflow.com/questions/29328124/no-bean-resolver-registered-in-the-context-to-resolve-access-to-bean