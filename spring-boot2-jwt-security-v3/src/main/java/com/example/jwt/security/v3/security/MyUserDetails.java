package com.example.jwt.security.v3.security;

import com.example.jwt.security.v3.model.Role;
import com.example.jwt.security.v3.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

public class MyUserDetails extends org.springframework.security.core.userdetails.User implements UserDetails {

    private User user;

    private List<Role> roles;

    public MyUserDetails(User user, List<Role> roles) {
        super(user.getUsername(), user.getPassword(), getAuthorities(roles));
        this.user = user;
        this.roles = roles;
    }

    public static Collection<GrantedAuthority> getAuthorities(List<Role> roles) {
        List<GrantedAuthority> authorities = new ArrayList<>();

        if (roles != null && !roles.isEmpty()) {
            authorities = roles.stream().map(new Function<Role, GrantedAuthority>() {
                /**
                 * hasRole 判断角色前面加 "ROLE_"
                 * hasAuthority 不需要加任何前缀
                 * @return SimpleGrantedAuthority
                 */
                @Override
                public GrantedAuthority apply(Role role) {
                    return new SimpleGrantedAuthority(role.name());
                }
            }).collect(Collectors.toList());
        }
        return authorities;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public List<Role> getRoles() {
        return roles;
    }

    public void setRoles(List<Role> roles) {
        this.roles = roles;
    }

    @Override
    public String toString() {
        return "SecurityUser{" +
            "user=" + user +
            ", roles=" + roles +
            '}';
    }
}