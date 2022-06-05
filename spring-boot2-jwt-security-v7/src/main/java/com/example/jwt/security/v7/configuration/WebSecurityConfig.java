package com.example.jwt.security.v7.configuration;

import com.example.jwt.security.v7.exception.RestfulAccessDeniedHandler;
import com.example.jwt.security.v7.security.JwtLoginFilter;
import com.example.jwt.security.v7.security.JwtTokenFilter;
import com.example.jwt.security.v7.security.JwtTokenProvider;
import com.example.jwt.security.v7.security.MyAccessDecisionManager;
import com.example.jwt.security.v7.security.MyFilter;
import com.example.jwt.security.v7.security.MyFilterInvocationSecurityMetadataSource;
import com.example.jwt.security.v7.security.MyFilterSecurityInterceptor;
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
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.HashMap;
import java.util.Map;

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
        String idForEncode = "bcrypt";
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(12);
        encoders.put(idForEncode, bCryptPasswordEncoder);
        encoders.put("noop", NoOpPasswordEncoder.getInstance());
        encoders.put("sha256", new StandardPasswordEncoder());
        encoders.put("scrypt", new SCryptPasswordEncoder());

        // User{id=3, username='admin', password='{bcrypt}$2a$12$kgM/Xn5sCED9SeWIPeWjJ.jbKCgFLXEmpogIHD6wA9RlbV9JnBGIC', privileges=[Privilege{id=3, name='ADMIN_PRIVILEGE'}], organization=Organization{id=1, name='user.org1'}}
        return new DelegatingPasswordEncoder(idForEncode, encoders);
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
        myFilterSecurityInterceptor.setSecurityMetadataSource(new MyFilterInvocationSecurityMetadataSource());
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

