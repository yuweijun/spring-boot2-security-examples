package com.example.jwt.security.v2.configuration;

import com.example.jwt.security.v2.exception.RestAuthenticationEntryPoint;
import com.example.jwt.security.v2.exception.RestfulAccessDeniedHandler;
import com.example.jwt.security.v2.security.JwtLoginFilter;
import com.example.jwt.security.v2.security.JwtTokenFilter;
import com.example.jwt.security.v2.security.JwtTokenProvider;
import com.example.jwt.security.v2.security.MyFilter;
import com.example.jwt.security.v2.security.MyFilterSecurityInterceptor;
import com.example.jwt.security.v2.security.MySecurityMetadataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Order(90)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebSecurityConfig.class);

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private RestfulAccessDeniedHandler restfulAccessDeniedHandler;

    @Autowired
    private RestAuthenticationEntryPoint restAuthenticationEntryPoint;

    @Autowired
    private UserDetailsService userDetailsService;

    @Value("${server.stateless:true}")
    private boolean stateless;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        LOGGER.info("begin configure http security");
        // Disable CSRF (cross site request forgery)
        http.csrf().disable();

        // Entry points
        http.authorizeRequests()
            .antMatchers("/", "/login", "/home").permitAll()
            .antMatchers("/users/signin").permitAll()
            .antMatchers("/users/signup").permitAll()
            .antMatchers("/h2-console/**/**").permitAll()
            .antMatchers("/assets/**").permitAll()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/**").hasAnyRole("ADMIN", "CLIENT", "USER")
            .anyRequest().authenticated();

        LOGGER.warn("server.stateless is {}", stateless);
        if (stateless) {
            // No session will be created or used by spring security
            http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        } else {
            // formLogin() will use session to store Authentication
            http.formLogin()
                .loginPage("/login")
                .successHandler((request, response, authentication) -> {
                    LOGGER.info("login successfully");
                })
                .failureHandler((request, response, exception) -> {
                    LOGGER.info("login failed");
                }).permitAll();

            http.logout().logoutUrl("/logout").permitAll()
                .deleteCookies("remember-me")
                .invalidateHttpSession(true).permitAll();

            http.rememberMe().tokenValiditySeconds(1209600);
        }

        // Registration of multiple Filters in the same location means their ordering is not deterministic.
        // More concretely, registering multiple Filters in the same location does not override existing Filters.
        // Instead, do not register Filters you do not want to use.
        http.addFilterBefore(jwtLoginFilter(), UsernamePasswordAuthenticationFilter.class)
            .addFilterAt(new JwtTokenFilter(jwtTokenProvider), BasicAuthenticationFilter.class)
            .addFilterAt(new MyFilter(), LogoutFilter.class)
            .addFilterBefore(myFilterSecurityInterceptor(), FilterSecurityInterceptor.class);

        http.exceptionHandling()
            .accessDeniedHandler(restfulAccessDeniedHandler)
            .authenticationEntryPoint(restAuthenticationEntryPoint);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        LOGGER.info("begin configure web security");
        // Allow swagger to be accessed without authentication
        web.ignoring().antMatchers("/v2/api-docs")
           .antMatchers("/swagger-resources/**")
           .antMatchers("/swagger-ui.html")
           .antMatchers("/configuration/**")
           .antMatchers("/webjars/**")
           .antMatchers("/public")

           // Un-secure H2 Database (for testing purposes, H2 console shouldn't be unprotected in production)
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
        myFilterSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());
        myFilterSecurityInterceptor.setSecurityMetadataSource(new MySecurityMetadataSource());
        return myFilterSecurityInterceptor;
    }

    private AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<?>> decisionVoters = new ArrayList<>();
        decisionVoters.add(new WebExpressionVoter());
        decisionVoters.add(new RoleVoter());
        decisionVoters.add(new AuthenticatedVoter());
        return new AffirmativeBased(decisionVoters);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        LOGGER.info("create bean AuthenticationManager");
        return super.authenticationManagerBean();
    }
}
