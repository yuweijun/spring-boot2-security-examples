package com.example.spring.boot2.simple.security.core;

import java.io.Serializable;
import java.security.Principal;
import java.util.Collection;

public interface Authentication extends Principal, Serializable {

	Collection<String> getAuthorities();

	String getPrincipal();

	boolean isAuthenticated();

	void setAuthenticated(boolean authenticated);

}
