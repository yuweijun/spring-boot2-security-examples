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


# FilterChain -> tomcat ApplicationFilterChain

    this = {ApplicationFilterChain@11868}
    filters = {ApplicationFilterConfig[10]@12574}
    0 = {ApplicationFilterConfig@12577} "ApplicationFilterConfig[name=characterEncodingFilter, filterClass=org.springframework.boot.web.servlet.filter.OrderedCharacterEncodingFilter]"
    1 = {ApplicationFilterConfig@12578} "ApplicationFilterConfig[name=webMvcMetricsFilter, filterClass=org.springframework.boot.actuate.metrics.web.servlet.WebMvcMetricsFilter]"
    2 = {ApplicationFilterConfig@12579} "ApplicationFilterConfig[name=formContentFilter, filterClass=org.springframework.boot.web.servlet.filter.OrderedFormContentFilter]"
    3 = {ApplicationFilterConfig@12580} "ApplicationFilterConfig[name=requestContextFilter, filterClass=org.springframework.boot.web.servlet.filter.OrderedRequestContextFilter]"
    4 = {ApplicationFilterConfig@12581} "ApplicationFilterConfig[name=springSecurityFilterChain, filterClass=org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean$1]"
    5 = {ApplicationFilterConfig@12582} "ApplicationFilterConfig[name=jwtLoginFilter, filterClass=com.example.jwt.security.v4.security.JwtLoginFilter]"
    6 = {ApplicationFilterConfig@12583} "ApplicationFilterConfig[name=Tomcat WebSocket (JSR356) Filter, filterClass=org.apache.tomcat.websocket.server.WsFilter]"

# filterChainProxy and filterChains

    this = {FilterChainProxy@11871} "FilterChainProxy[Filter Chains: [[ Ant [pattern='/v2/api-docs'], []], [ Ant [pattern='/favicon.ico'], []], [ Ant [pattern='/swagger-resources/**'], []], [ Ant [pattern='/swagger-ui.html'], []], [ Ant [pattern='/configuration/**'], []], [ Ant [pattern='/webjars/**'], []], [ Ant [pattern='/manage/**'], []], [ Ant [pattern='/h2-console/**/**'], []], [ Ant [pattern='/assets/**'], []], [ Ant [pattern='/public'], []], [ Ant [pattern='/h2-console/**/**'], []], [ Ant [pattern='/admin/**'], [org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@790ebd26, org.springframework.security.web.context.SecurityContextPersistenceFilter@9ba30a, org.springframework.security.web.header.HeaderWriterFilter@1a1abafc, org.springframework.security.web.authentication.logout.LogoutFilter@2a834adb, org.springframework.security.web.authentication.www.BasicAuthenticationFilter@53a79964, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@3de61f5f, org.springframewo"
    filterChains = {ArrayList@11874}  size = 13
    0 = {DefaultSecurityFilterChain@12647} "[ Ant [pattern='/v2/api-docs'], []]"
    1 = {DefaultSecurityFilterChain@12648} "[ Ant [pattern='/favicon.ico'], []]"
    2 = {DefaultSecurityFilterChain@12649} "[ Ant [pattern='/swagger-resources/**'], []]"
    3 = {DefaultSecurityFilterChain@12650} "[ Ant [pattern='/swagger-ui.html'], []]"
    4 = {DefaultSecurityFilterChain@12651} "[ Ant [pattern='/configuration/**'], []]"
    5 = {DefaultSecurityFilterChain@12652} "[ Ant [pattern='/webjars/**'], []]"
    6 = {DefaultSecurityFilterChain@12653} "[ Ant [pattern='/manage/**'], []]"
    7 = {DefaultSecurityFilterChain@12654} "[ Ant [pattern='/h2-console/**/**'], []]"
    8 = {DefaultSecurityFilterChain@12655} "[ Ant [pattern='/assets/**'], []]"
    9 = {DefaultSecurityFilterChain@12656} "[ Ant [pattern='/public'], []]"
    10 = {DefaultSecurityFilterChain@12657} "[ Ant [pattern='/h2-console/**/**'], []]"
    11 = {DefaultSecurityFilterChain@12591} "[ Ant [pattern='/admin/**'], [org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@790ebd26, org.springframework.security.web.context.SecurityContextPersistenceFilter@9ba30a, org.springframework.security.web.header.HeaderWriterFilter@1a1abafc, org.springframework.security.web.authentication.logout.LogoutFilter@2a834adb, org.springframework.security.web.authentication.www.BasicAuthenticationFilter@53a79964, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@3de61f5f, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@64414033, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@7c02a24e, org.springframework.security.web.session.SessionManagementFilter@3b1b565a, org.springframework.security.web.access.ExceptionTranslationFilter@1b0d9068, org.springframework.security.web.access.intercept.FilterSecurityInterceptor@7ea33eb8]]"
    12 = {DefaultSecurityFilterChain@11885} "[ any request, [org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@5c90d68, org.springframework.security.web.context.SecurityContextPersistenceFilter@4fe6135f, org.springframework.security.web.header.HeaderWriterFilter@1d876f81, com.example.jwt.security.v4.security.MyFilter@2ef8e47b, org.springframework.security.web.authentication.logout.LogoutFilter@6bd5cb3a, com.example.jwt.security.v4.security.JwtLoginFilter@57c82f15, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter@384232ad, com.example.jwt.security.v4.security.JwtTokenFilter@2fbb9013, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@3699d2cc, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@104448f9, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@6451813, org.springframework.security.web.session.SessionManagementFilter@9c1baf7, org.springframework.security.web.access.Except"

# chain and filters for request /login

    [ any request, [org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@5c90d68, org.springframework.security.web.context.SecurityContextPersistenceFilter@4fe6135f, org.springframework.security.web.header.HeaderWriterFilter@1d876f81, com.example.jwt.security.v4.security.MyFilter@2ef8e47b, org.springframework.security.web.authentication.logout.LogoutFilter@6bd5cb3a, com.example.jwt.security.v4.security.JwtLoginFilter@57c82f15, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter@384232ad, com.example.jwt.security.v4.security.JwtTokenFilter@2fbb9013, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@3699d2cc, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@104448f9, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@6451813, org.springframework.security.web.session.SessionManagementFilter@9c1baf7, org.springframework.security.web.access.ExceptionTranslationFilter@4737d631, com.example.jwt.security.v4.security.MyFilterSecurityInterceptor@4b2af7fe, org.springframework.security.web.access.intercept.FilterSecurityInterceptor@2e40ab49]]

    filters = {ArrayList@11890}  size = 15
    0 = {WebAsyncManagerIntegrationFilter@11896}
    1 = {SecurityContextPersistenceFilter@11897}
    2 = {HeaderWriterFilter@11898}
    3 = {MyFilter@11899}
    4 = {LogoutFilter@11900}
    5 = {JwtLoginFilter@11901}
    6 = {UsernamePasswordAuthenticationFilter@11902}
    7 = {JwtTokenFilter@11903}
    8 = {RequestCacheAwareFilter@11904}
    9 = {SecurityContextHolderAwareRequestFilter@11905}
    10 = {AnonymousAuthenticationFilter@11906}
    11 = {SessionManagementFilter@11907}
    12 = {ExceptionTranslationFilter@11908}
    13 = {MyFilterSecurityInterceptor@11909}
    14 = {FilterSecurityInterceptor@11910}

# chain and filters for request /admin/**

    chain = {DefaultSecurityFilterChain@12591} "[ Ant [pattern='/admin/**'], [org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter@790ebd26, org.springframework.security.web.context.SecurityContextPersistenceFilter@9ba30a, org.springframework.security.web.header.HeaderWriterFilter@1a1abafc, org.springframework.security.web.authentication.logout.LogoutFilter@2a834adb, org.springframework.security.web.authentication.www.BasicAuthenticationFilter@53a79964, org.springframework.security.web.savedrequest.RequestCacheAwareFilter@3de61f5f, org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter@64414033, org.springframework.security.web.authentication.AnonymousAuthenticationFilter@7c02a24e, org.springframework.security.web.session.SessionManagementFilter@3b1b565a, org.springframework.security.web.access.ExceptionTranslationFilter@1b0d9068, org.springframework.security.web.access.intercept.FilterSecurityInterceptor@7ea33eb8]]"
    requestMatcher = {AntPathRequestMatcher@12595} "Ant [pattern='/admin/**']"
    filters = {ArrayList@12596}  size = 11
    0 = {WebAsyncManagerIntegrationFilter@12599}
    1 = {SecurityContextPersistenceFilter@12600}
    2 = {HeaderWriterFilter@12601}
    3 = {LogoutFilter@12602}
    4 = {BasicAuthenticationFilter@12603}
    5 = {RequestCacheAwareFilter@12604}
    6 = {SecurityContextHolderAwareRequestFilter@12605}
    7 = {AnonymousAuthenticationFilter@12606}
    8 = {SessionManagementFilter@12607}
    9 = {ExceptionTranslationFilter@12608}
    10 = {FilterSecurityInterceptor@12609}

# /admin/** securityFilterChainBuilder call stack

    addSecurityFilterChainBuilder:202, WebSecurity (org.springframework.security.config.annotation.web.builders)
    init:323, WebSecurityConfigurerAdapter (org.springframework.security.config.annotation.web.configuration)
    init:94, WebSecurityConfigurerAdapter (org.springframework.security.config.annotation.web.configuration)
    init:-1, MultiHttpSecurityConfig$WebAdminSecurityConfig$$EnhancerBySpringCGLIB$$e3bed984 (com.example.jwt.security.v4.configuration)

    init:370, AbstractConfiguredSecurityBuilder (org.springframework.security.config.annotation)

    doBuild:324, AbstractConfiguredSecurityBuilder (org.springframework.security.config.annotation)
    build:41, AbstractSecurityBuilder (org.springframework.security.config.annotation)
    springSecurityFilterChain:104, WebSecurityConfiguration (org.springframework.security.config.annotation.web.configuration)
    invoke0:-1, NativeMethodAccessorImpl (jdk.internal.reflect)
    invoke:62, NativeMethodAccessorImpl (jdk.internal.reflect)
    invoke:43, DelegatingMethodAccessorImpl (jdk.internal.reflect)
    invoke:566, Method (java.lang.reflect)
    instantiate:154, SimpleInstantiationStrategy (org.springframework.beans.factory.support)
    instantiate:650, ConstructorResolver (org.springframework.beans.factory.support)
    instantiateUsingFactoryMethod:483, ConstructorResolver (org.springframework.beans.factory.support)
    instantiateUsingFactoryMethod:1336, AbstractAutowireCapableBeanFactory (org.springframework.beans.factory.support)
    createBeanInstance:1176, AbstractAutowireCapableBeanFactory (org.springframework.beans.factory.support)
    doCreateBean:556, AbstractAutowireCapableBeanFactory (org.springframework.beans.factory.support)
    createBean:516, AbstractAutowireCapableBeanFactory (org.springframework.beans.factory.support)
    lambda$doGetBean$0:324, AbstractBeanFactory (org.springframework.beans.factory.support)
    getObject:-1, 486208025 (org.springframework.beans.factory.support.AbstractBeanFactory$$Lambda$231)
    getSingleton:226, DefaultSingletonBeanRegistry (org.springframework.beans.factory.support)
    doGetBean:322, AbstractBeanFactory (org.springframework.beans.factory.support)
    getBean:202, AbstractBeanFactory (org.springframework.beans.factory.support)
    doGetBean:311, AbstractBeanFactory (org.springframework.beans.factory.support)
    getBean:202, AbstractBeanFactory (org.springframework.beans.factory.support)
    ...
    run:49, RestartLauncher (org.springframework.boot.devtools.restart)

# com.example.jwt.security.v4.configuration.MultiHttpSecurityConfig init related methods

## org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder

	@Override
	protected final O doBuild() throws Exception {
		synchronized (configurers) {
			buildState = BuildState.INITIALIZING;

			beforeInit();
			init();

			buildState = BuildState.CONFIGURING;

			beforeConfigure();
			configure();

			buildState = BuildState.BUILDING;

			O result = performBuild();

			buildState = BuildState.BUILT;

			return result;
		}
	}

	private void init() throws Exception {
		Collection<SecurityConfigurer<O, B>> configurers = getConfigurers();

		for (SecurityConfigurer<O, B> configurer : configurers) {
			configurer.init((B) this);
		}

		for (SecurityConfigurer<O, B> configurer : configurersAddedInInitializing) {
			configurer.init((B) this);
		}
	}

## org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter

	public void init(final WebSecurity web) throws Exception {
		final HttpSecurity http = getHttp();
		web.addSecurityFilterChainBuilder(http).postBuildAction(() -> {
			FilterSecurityInterceptor securityInterceptor = http
					.getSharedObject(FilterSecurityInterceptor.class);
			web.securityInterceptor(securityInterceptor);
		});
	}


# References

1. https://stackoverflow.com/questions/29328124/no-bean-resolver-registered-in-the-context-to-resolve-access-to-bean