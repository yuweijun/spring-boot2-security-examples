# including MyAuthenticationProvider for username/password authentication

# including MultiHttpSecurityConfig

# The bean 'methodSecurityInterceptor', defined in class path resource [org/springframework/security/config/annotation/method/configuration/GlobalMethodSecurityConfiguration.class], could not be registered. A bean with that name has already been defined in class path resource [com/example/jwt/security/v3/configuration/MyMethodSecurityFirstConfig.class] and overriding is disabled.

The error is expected behaviour. The GlobalMethodSecurityConfiguration Javadoc states:

    Base Configuration for enabling global method security. Classes may extend this class to customize the defaults, 
    but must be sure to specify the EnableGlobalMethodSecurity annotation on the subclass.

This is necessary so that Spring Security can detect if GlobalMethodSecurityConfiguration needs imported or not. If we do anything to try and prevent this, it will trigger eager bean initialization because AOP related beans need to be created very early. Eager bean initialization can trigger beans to not be proxied properly which would mean security, transactions, and other AOP would not be applied properly.

# References

1. https://github.com/spring-projects/spring-security/issues/8684
2. https://docs.spring.io/spring-security/site/docs/5.3.3.RELEASE/reference/html5/#multiple-httpsecurity
3. https://stackoverflow.com/questions/33603156/spring-security-multiple-http-config-not-working
4. https://felord.cn/webSecurity-httpSecurity.html