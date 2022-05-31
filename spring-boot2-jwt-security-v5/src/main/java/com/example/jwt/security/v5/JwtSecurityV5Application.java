package com.example.jwt.security.v5;

import com.example.jwt.security.v5.configuration.EnableJwtSecurity;
import com.example.jwt.security.v5.model.Organization;
import com.example.jwt.security.v5.model.Privilege;
import com.example.jwt.security.v5.model.User;
import com.example.jwt.security.v5.repository.OrganizationRepository;
import com.example.jwt.security.v5.repository.PrivilegeRepository;
import com.example.jwt.security.v5.repository.UserRepository;
import com.example.jwt.security.v5.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;
import java.util.HashSet;

@EnableJwtSecurity
@SpringBootApplication
public class JwtSecurityV5Application implements CommandLineRunner {

    @Autowired
    UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PrivilegeRepository privilegeRepository;

    @Autowired
    private OrganizationRepository organizationRepository;

    public static void main(String[] args) {
        SpringApplication.run(JwtSecurityV5Application.class, args);
    }

    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }

    @Override
    public void run(String... params) throws Exception {
        Privilege userRead = new Privilege();
        userRead.setName("USER_PRIVILEGE");
        privilegeRepository.save(userRead);

        Privilege userWrite = new Privilege();
        userWrite.setName("USER_WRITE_PRIVILEGE");
        privilegeRepository.save(userWrite);

        Privilege adminPrivilege = new Privilege();
        adminPrivilege.setName("ADMIN_PRIVILEGE");
        privilegeRepository.save(adminPrivilege);

        Privilege clientRead = new Privilege();
        clientRead.setName("CLIENT_PRIVILEGE");
        privilegeRepository.save(clientRead);

        Privilege clientWrite = new Privilege();
        clientWrite.setName("CLIENT_WRITE_PRIVILEGE");
        privilegeRepository.save(clientWrite);

        Organization org1 = new Organization();
        org1.setName("user.org1");
        organizationRepository.save(org1);

        Organization org2 = new Organization();
        org2.setName("client.org2");
        organizationRepository.save(org2);

        User user = new User();
        user.setUsername("user");
        user.setPassword(passwordEncoder.encode("user"));

        user.setPrivileges(new HashSet<>(Arrays.asList(userRead, userWrite)));
        user.setOrganization(org1);
        userRepository.save(user);

        User client = new User();
        client.setUsername("client");
        client.setPassword(passwordEncoder.encode("client"));
        client.setPrivileges(new HashSet<>(Arrays.asList(clientRead, clientWrite)));
        client.setOrganization(org2);
        userRepository.save(client);

        User admin = new User();
        admin.setUsername("admin");
        admin.setPassword(passwordEncoder.encode("admin"));
        admin.setPrivileges(new HashSet<>(Arrays.asList(adminPrivilege)));
        admin.setOrganization(org1);
        userRepository.save(admin);
    }

}
