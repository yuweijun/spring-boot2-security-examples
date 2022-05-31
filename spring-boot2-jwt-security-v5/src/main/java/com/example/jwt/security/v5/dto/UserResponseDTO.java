package com.example.jwt.security.v5.dto;

import com.example.jwt.security.v5.model.Organization;
import io.swagger.annotations.ApiModelProperty;

import java.util.List;

public class UserResponseDTO {

    @ApiModelProperty(position = 3)
    List<Organization> roles;
    @ApiModelProperty(position = 0)
    private Integer id;
    @ApiModelProperty(position = 1)
    private String username;
    @ApiModelProperty(position = 2)
    private String email;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

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

    public List<Organization> getRoles() {
        return roles;
    }

    public void setRoles(List<Organization> roles) {
        this.roles = roles;
    }

}
