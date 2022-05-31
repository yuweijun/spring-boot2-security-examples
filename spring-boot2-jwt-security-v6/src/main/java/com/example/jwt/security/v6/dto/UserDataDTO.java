package com.example.jwt.security.v6.dto;

import com.example.jwt.security.v6.model.Organization;
import io.swagger.annotations.ApiModelProperty;

import java.util.List;

public class UserDataDTO {

    @ApiModelProperty(position = 3)
    List<Organization> roles;
    @ApiModelProperty(position = 0)
    private String username;
    @ApiModelProperty(position = 1)
    private String email;
    @ApiModelProperty(position = 2)
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public List<Organization> getRoles() {
        return roles;
    }

    public void setRoles(List<Organization> roles) {
        this.roles = roles;
    }

}
