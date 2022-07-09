# including thymeleaf and web form login

# including MySecurityMetadataSource and JwtSecurityImportBeanDefinitionRegistrar

## thymeleaf sec:authorize not working in spring boot

    implementation 'org.thymeleaf.extras:thymeleaf-extras-springsecurity5'

# Spring Security Configuration - HttpSecurity vs WebSecurity

General use of WebSecurity ignoring() method omits Spring Security and none of Spring Security’s features will be available. WebSecurity is based above HttpSecurity.

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
        .ignoring()
        .antMatchers("/resources/**")
        .antMatchers("/publics/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
        .authorizeRequests()
        .antMatchers("/admin/**").hasRole("ADMIN")
        .antMatchers("/publics/**").hasRole("USER") // no effect
        .anyRequest().authenticated();
    }

WebSecurity in the above example lets Spring ignore /resources/** and /publics/**. Therefore the .antMatchers("/publics/**").hasRole("USER") in HttpSecurity is unconsidered.

This will omit the request pattern from the security filter chain entirely. Note that anything matching this path will then have no authentication or authorization services applied and will be freely accessible.

configure(HttpSecurity) allows configuration of web-based security at a resource level, based on a selection match - e.g. The example below restricts the URLs that start with /admin/ to users that have ADMIN role, and declares that any other URLs need to be successfully authenticated.

configure(WebSecurity) is used for configuration settings that impact global security (ignore resources, set debug mode, reject requests by implementing a custom firewall definition). For example, the following method would cause any request that starts with /resources/ to be ignored for authentication purposes.

Let's consider the below code, we can ignore the authentication for the endpoint provided within antMatchers using both the methods.

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
        .ignoring()
        .antMatchers("/login", "/register", "/api/public/**");
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeRequests()
            .antMatchers("/login", "/register", "/api/public/**").permitAll()
            .anyRequest().authenticated();
    }

configure(WebSecurity web) Endpoint used in this method ignores the spring security filters, security features (secure headers, csrf protection etc) are also ignored and no security context will be set and can not protect endpoints for Cross-Site Scripting, XSS attacks, content-sniffing.

configure(HttpSecurity http) Endpoint used in this method ignores the authentication for endpoints used in antMatchers and other security features will be in effect such as secure headers, CSRF protection, etc.

# 有三个具体的 AccessDecisionManager 提供了 Spring 安全，以统计选票。

1. ConsensusBased实现将基于非弃权投票的共识授予或拒绝访问，在票数相等或所有投票都弃权的情况下，提供属性以控制行为。
2. 如果收到一个或多个ACCESS_GRANTED投票，AffirmativeBased实现将授予访问权限（即，如果至少有一个授予投票，则拒绝投票将被忽略），与ConsensusBased实现类似，如果所有投票者弃权，则有一个参数来控制行为。
3. UnanimousBased提供者期望获得一致的ACCESS_GRANTED票，以授予访问权限，而忽略弃权，如果有任何ACCESS_DENIED投票，它将拒绝访问，与其他实现一样，如果所有投票者都弃权，则有一个控制行为的参数。

# References

1. https://stackoverflow.com/questions/55197139/thymeleaf-secauthorize-not-working-in-spring-boot
2. https://stackoverflow.com/questions/56388865/spring-security-configuration-httpsecurity-vs-websecurity
3. https://www.springcloud.io/post/2022-02/websecurity-and-httpsecurity/#gsc.tab=0
4. https://github.com/planitian/sercurity