package com.example.jwt.security.v6.configuration;

import com.example.jwt.security.v6.exception.RestfulAccessDeniedHandler;
import com.example.jwt.security.v6.security.JwtLoginFilter;
import com.example.jwt.security.v6.security.JwtTokenFilter;
import com.example.jwt.security.v6.security.JwtTokenProvider;
import com.example.jwt.security.v6.security.MyAccessDecisionManager;
import com.example.jwt.security.v6.security.MyFilter;
import com.example.jwt.security.v6.security.MyFilterSecurityInterceptor;
import com.example.jwt.security.v6.security.MySecurityMetadataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
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
 * disable annotation @EnableGlobalMethodSecurity in class {@link WebSecurityConfig} avoid error:
 * The bean 'methodSecurityInterceptor', defined in class path resource [org/springframework/security/config/annotation/method/configuration/GlobalMethodSecurityConfiguration.class], could not be registered. A bean with that name has already been defined in class path resource [com/example/jwt/security/v3/configuration/MyMethodSecurityFirstConfig.class] and overriding is disabled.
 *
 * Base Configuration for enabling global method security.
 * Classes may extend this class to customize the defaults,
 * but must be sure to specify the EnableGlobalMethodSecurity annotation on the subclass.
 * </pre>
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebSecurityConfig.class);

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        LOGGER.info("WebSecurityConfig begin configure http security : {}", http);

        http.csrf().disable();

        http.authorizeRequests()
            .antMatchers("/", "/login", "/home").permitAll()
            .antMatchers("/users/signin").permitAll()
            .antMatchers("/users/signup").permitAll()
            .antMatchers("/admin/**").hasAuthority("ADMIN_PRIVILEGE")
            .antMatchers("/**").hasAnyAuthority("ADMIN_PRIVILEGE", "CLIENT_PRIVILEGE", "USER_PRIVILEGE")
            .anyRequest()
            .authenticated()
            .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                @Override
                public <T extends FilterSecurityInterceptor> T postProcess(T object) {
                    LOGGER.info("getSecurityMetadataSource : {}", object.getSecurityMetadataSource());
                    LOGGER.info("getAccessDecisionManager : {}", object.getAccessDecisionManager());
                    return object;
                }
            })
            .and()
            .formLogin(withDefaults());

        http.addFilterBefore(jwtLoginFilter(), UsernamePasswordAuthenticationFilter.class)
            .addFilterAt(new JwtTokenFilter(jwtTokenProvider), BasicAuthenticationFilter.class)
            .addFilterAt(new MyFilter(), LogoutFilter.class)
            .addFilterBefore(myFilterSecurityInterceptor(), FilterSecurityInterceptor.class);

        // http.exceptionHandling().accessDeniedPage("/login");
        http.exceptionHandling()
            .accessDeniedHandler(restfulAccessDeniedHandler());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // web.debug(true);
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

    @Bean
    public RestfulAccessDeniedHandler restfulAccessDeniedHandler() {
        return new RestfulAccessDeniedHandler();
    }

}

