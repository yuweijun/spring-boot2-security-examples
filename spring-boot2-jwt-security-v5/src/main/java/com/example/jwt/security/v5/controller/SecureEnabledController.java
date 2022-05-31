package com.example.jwt.security.v5.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;

@RestController
@RequestMapping("/example")
public class SecureEnabledController {

    /**
     * {@link org.springframework.security.access.vote.RoleVoter#vote(Authentication, Object, Collection)}
     *
     * MUST add prefix ROLE_ before authorities name, so voter.vote() will fail if authentication's authority name is not start with ROLE_
     *
     * <pre>
     * for (ConfigAttribute attribute : attributes) {
     *     if (this.supports(attribute)) {
     *         result = ACCESS_DENIED;
     *
     *         // Attempt to find a matching granted authority
     *         for (GrantedAuthority authority : authorities) {
     *             if (attribute.getAttribute().equals(authority.getAuthority())) {
     *                 return ACCESS_GRANTED;
     *             }
     *         }
     *     }
     * }
     * </pre>
     *
     * override AccessDecisionManager and add new RoleVoter and setPrefix of RoleVoter if we need support secureEnabled
     *
     * <pre>
     * if (accessDecisionManager instanceof AffirmativeBased) {
     *     AffirmativeBased affirmativeBased = (AffirmativeBased) accessDecisionManager;
     *     final List<AccessDecisionVoter<?>> decisionVoters = affirmativeBased.getDecisionVoters();
     *     RoleVoter roleVoter = new RoleVoter();
     *     roleVoter.setRolePrefix("");
     *     decisionVoters.add(roleVoter);
     * }
     *
     * </pre>
     */
    @Secured({"ROLE_ADMIN_PRIVILEGE", "ROLE_USER_PRIVILEGE"})
    @GetMapping("/secured")
    public String secured() {
        return "org.springframework.security.access.AccessDeniedException: Access is denied for secureEnabled@Secured because privileges name do not prefix ROLE_";
    }

    @GetMapping("/test")
    public String test() {
        return "test without spring security annotation";
    }

}
