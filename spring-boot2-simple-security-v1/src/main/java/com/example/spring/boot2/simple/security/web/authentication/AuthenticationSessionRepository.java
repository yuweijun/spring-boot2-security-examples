package com.example.spring.boot2.simple.security.web.authentication;

import com.example.spring.boot2.simple.security.core.context.SecurityContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * @author yuweijun 2022-06-25.
 */
public class AuthenticationSessionRepository {

    private static final String SECURITY_CONTEXT = "SecurityContext";

    public SecurityContext loadContext(HttpServletRequest request) {
        HttpSession session = request.getSession();
        SecurityContext context = (SecurityContext) session.getAttribute(SECURITY_CONTEXT);
        return context;
    }

    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession();
        session.setAttribute(SECURITY_CONTEXT, context);
    }

}
