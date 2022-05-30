package com.example.jwt.security.v1.configuration;

import com.example.jwt.security.v1.security.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebSecurityConfig.class);

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        LOGGER.info("begin configure http security");
        http.csrf().disable();

        http.authorizeRequests()
            .antMatchers("/", "/home").permitAll()
            .antMatchers("/users/signin").permitAll()
            .antMatchers("/users/signup").permitAll()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/**").hasAnyRole("ADMIN", "CLIENT", "USER")
            .anyRequest()
            .authenticated();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.exceptionHandling().accessDeniedPage("/login");

        http.apply(new JwtTokenFilterConfig(jwtTokenProvider));
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
           .antMatchers("/h2-console/**/**")
           .antMatchers("/assets/**")
           .antMatchers("/public")

           // Un-secure H2 Database (for testing purposes, H2 console shouldn't be unprotected in production)
           .and()
           .ignoring()
           .antMatchers("/h2-console/**/**");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * 对于低版本的Spring Security，添加注解之后还需要将AuthenticationManager定义为Bean
     *
     * org.springframework.beans.factory.NoSuchBeanDefinitionException: No qualifying bean of type 'org.springframework.security.authentication.AuthenticationManager'
     * <pre>
     * @Bean
     * @Override
     * public AuthenticationManager authenticationManager() throws Exception {
     *      return super.authenticationManager();
     * }
     *
     * 也可以覆写上面这个方法
     * https://stackoverflow.com/questions/21633555/how-to-inject-authenticationmanager-using-java-configuration-in-a-custom-filter
     * </pre>
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        LOGGER.info("create bean AuthenticationManager");
        return super.authenticationManagerBean();
    }
}
