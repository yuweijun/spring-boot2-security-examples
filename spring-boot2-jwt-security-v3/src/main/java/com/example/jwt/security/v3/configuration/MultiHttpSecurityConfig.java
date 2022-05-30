package com.example.jwt.security.v3.configuration;

import com.example.jwt.security.v3.exception.RestAuthenticationEntryPoint;
import com.example.jwt.security.v3.exception.RestfulAccessDeniedHandler;
import com.example.jwt.security.v3.security.JwtLoginFilter;
import com.example.jwt.security.v3.security.JwtTokenFilter;
import com.example.jwt.security.v3.security.JwtTokenProvider;
import com.example.jwt.security.v3.security.MyAccessDecisionManager;
import com.example.jwt.security.v3.security.MyFilter;
import com.example.jwt.security.v3.security.MyFilterSecurityInterceptor;
import com.example.jwt.security.v3.security.MySecurityMetadataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * <pre>
 * We can actually consider that WebSecurity is the only external outlet for Spring Security,
 * while HttpSecurity is just the way internal security policies are defined.
 *
 * 1. https://www.springcloud.io/post/2022-02/websecurity-and-httpsecurity/#gsc.tab=0
 * 2. https://stackoverflow.com/questions/56388865/spring-security-configuration-httpsecurity-vs-websecurity
 * 3. https://docs.spring.io/spring-security/site/docs/5.3.3.RELEASE/reference/html5/#multiple-httpsecurity
 * </pre>
 */
@EnableWebSecurity
public class MultiHttpSecurityConfig {

    /**
     * <pre>
     * disable annotation @EnableGlobalMethodSecurity in class {@link WebAdminSecurityConfig} avoid error:
     * The bean 'methodSecurityInterceptor', defined in class path resource [org/springframework/security/config/annotation/method/configuration/GlobalMethodSecurityConfiguration.class], could not be registered. A bean with that name has already been defined in class path resource [com/example/jwt/security/v3/configuration/MyMethodSecurityFirstConfig.class] and overriding is disabled.
     *
     * Base Configuration for enabling global method security.
     * Classes may extend this class to customize the defaults,
     * but must be sure to specify the EnableGlobalMethodSecurity annotation on the subclass.
     * </pre>
     */
    @Order(20)
    @Configuration
    // @EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
    public static class WebAdminSecurityConfig extends WebSecurityConfigurerAdapter {

        private static final Logger LOGGER = LoggerFactory.getLogger(WebAdminSecurityConfig.class);

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            LOGGER.info("WebAdminSecurityConfig begin configure http security : {}", http);
            http.csrf().disable();

            http.antMatcher("/admin/**")
                .authorizeRequests(authorize -> authorize.anyRequest().hasRole("ADMIN"))
                .httpBasic(withDefaults());
        }
    }

    /**
     * <pre>
     * Security filter chain: [
     *   WebAsyncManagerIntegrationFilter
     *   SecurityContextPersistenceFilter
     *   HeaderWriterFilter
     *   MyFilter
     *   LogoutFilter
     *   JwtLoginFilter
     *   UsernamePasswordAuthenticationFilter
     *   JwtTokenFilter
     *   RequestCacheAwareFilter
     *   SecurityContextHolderAwareRequestFilter
     *   AnonymousAuthenticationFilter
     *   SessionManagementFilter
     *   ExceptionTranslationFilter
     *   MyFilterSecurityInterceptor
     *   FilterSecurityInterceptor
     * ]
     * </pre>
     */
    @Order(10)
    @Configuration
    public static class WebSecurityConfig extends WebSecurityConfigurerAdapter {

        private static final Logger LOGGER = LoggerFactory.getLogger(WebSecurityConfig.class);

        @Autowired
        private JwtTokenProvider jwtTokenProvider;

        @Autowired
        private RestfulAccessDeniedHandler restfulAccessDeniedHandler;

        @Autowired
        private RestAuthenticationEntryPoint restAuthenticationEntryPoint;

        @Value("${server.stateless:true}")
        private boolean stateless;

        @Autowired
        private UserDetailsService userDetailsService;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            LOGGER.info("WebSecurityConfig begin configure http security : {}", http);

            http.csrf().disable();

            // Entry points
            http.authorizeRequests()
                .antMatchers("/", "/login", "/home").permitAll()
                .antMatchers("/users/signin").permitAll()
                .antMatchers("/users/signup").permitAll()

                // hasRole("ADMIN") should be declared before authenticated()
                // Caused by: role should not start with 'ROLE_' since it is automatically inserted. Got 'ROLE_ADMIN'
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/**").hasAnyRole("ADMIN", "CLIENT", "USER")
                .anyRequest()
                .authenticated()
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <T extends FilterSecurityInterceptor> T postProcess(T object) {
                        LOGGER.info("getSecurityMetadataSource : {}", object.getSecurityMetadataSource());
                        LOGGER.info("getAccessDecisionManager : {}", object.getAccessDecisionManager());
                        return object;
                    }
                });

            LOGGER.warn("server.stateless is {}", stateless);
            if (stateless) {
                // No session will be created or used by spring security
                http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
            } else {
                // formLogin() will use session to store Authentication
                http.formLogin(withDefaults());
            }

            // Registration of multiple Filters in the same location means their ordering is not deterministic.
            // More concretely, registering multiple Filters in the same location does not override existing Filters.
            // Instead, do not register Filters you do not want to use.
            http.addFilterBefore(jwtLoginFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterAt(new JwtTokenFilter(jwtTokenProvider), BasicAuthenticationFilter.class)
                .addFilterAt(new MyFilter(), LogoutFilter.class)
                .addFilterBefore(myFilterSecurityInterceptor(), FilterSecurityInterceptor.class);

            // If a user try to access a resource without having enough permissions
            // http.exceptionHandling().accessDeniedPage("/login");
            http.exceptionHandling()
                .accessDeniedHandler(restfulAccessDeniedHandler)
                .authenticationEntryPoint(restAuthenticationEntryPoint);
        }

        /**
         * <pre>
         * Override this method to configure WebSecurity.
         * For example, if you wish to ignore certain requests.
         *
         * General use of WebSecurity ignoring() method omits Spring Security and none of Spring Security’s features will be available.
         * WebSecurity is based above HttpSecurity.
         *
         * web.debug(true);
         * *******************************************************************
         * *********        Security debugging is enabled.       *************
         * *********    This may include sensitive information.  *************
         * *********      Do not use in a production system!     *************
         * *******************************************************************
         *
         * </pre>
         */
        @Override
        public void configure(WebSecurity web) throws Exception {
            web.debug(true);
            LOGGER.info("WebSecurityConfig begin configure web security : {}", web);

            web.ignoring().antMatchers("/v2/api-docs")
               .antMatchers("/favicon.ico")
               .antMatchers("/swagger-resources/**")
               .antMatchers("/swagger-ui.html")
               .antMatchers("/configuration/**")
               .antMatchers("/webjars/**")
               .antMatchers("/manage/**")
               .antMatchers("/h2-console/**/**")
               .antMatchers("/assets/**")
               .antMatchers("/public")

               .and()
               .ignoring()
               .antMatchers("/h2-console/**/**");
        }

        @Override
        protected void configure(AuthenticationManagerBuilder managerBuilder) throws Exception {
            // managerBuilder.authenticationProvider(myAuthenticationProvider);
            managerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder(12);
        }

        @Bean
        public JwtLoginFilter jwtLoginFilter() throws Exception {
            JwtLoginFilter jwtLoginFilter = new JwtLoginFilter();
            jwtLoginFilter.setAuthenticationManager(authenticationManagerBean());
            return jwtLoginFilter;
        }

        private MyFilterSecurityInterceptor myFilterSecurityInterceptor() {
            MyFilterSecurityInterceptor myFilterSecurityInterceptor = new MyFilterSecurityInterceptor();
            myFilterSecurityInterceptor.setAccessDecisionManager(new MyAccessDecisionManager());
            myFilterSecurityInterceptor.setSecurityMetadataSource(new MySecurityMetadataSource());
            return myFilterSecurityInterceptor;
        }

        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean() throws Exception {
            LOGGER.info("create bean AuthenticationManager");
            return super.authenticationManagerBean();
        }
    }

}
