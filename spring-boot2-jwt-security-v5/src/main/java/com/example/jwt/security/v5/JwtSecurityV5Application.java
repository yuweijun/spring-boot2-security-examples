package com.example.jwt.security.v5;

import com.example.jwt.security.v5.configuration.EnableJwtSecurity;
import com.example.jwt.security.v5.model.Role;
import com.example.jwt.security.v5.model.User;
import com.example.jwt.security.v5.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;
import java.util.Arrays;

@EnableJwtSecurity
@SpringBootApplication
public class JwtSecurityV5Application implements CommandLineRunner {

    @Autowired
    UserService userService;

    public static void main(String[] args) {
        SpringApplication.run(JwtSecurityV5Application.class, args);
    }

    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }

    @Override
    public void run(String... params) throws Exception {
        User admin = new User();
        admin.setUsername("admin");
        admin.setPassword("admin");
        admin.setEmail("admin@email.com");
        admin.setRoles(new ArrayList<>(Arrays.asList(Role.ROLE_ADMIN)));

        userService.signup(admin);

        User client = new User();
        client.setUsername("client");
        client.setPassword("client");
        client.setEmail("client@email.com");
        client.setRoles(new ArrayList<>(Arrays.asList(Role.ROLE_CLIENT)));

        userService.signup(client);

        User user = new User();
        user.setUsername("user");
        user.setPassword("user");
        user.setEmail("user@email.com");
        user.setRoles(new ArrayList<>(Arrays.asList(Role.ROLE_USER)));

        userService.signup(user);
    }

}
