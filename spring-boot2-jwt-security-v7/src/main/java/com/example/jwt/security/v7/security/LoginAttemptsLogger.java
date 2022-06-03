package com.example.jwt.security.v7.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class LoginAttemptsLogger {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginAttemptsLogger.class);

    @EventListener
    public void auditEventHappened(AuditApplicationEvent auditApplicationEvent) {
        AuditEvent auditEvent = auditApplicationEvent.getAuditEvent();
        LOGGER.info("Principal [{}-{}]", auditEvent.getPrincipal(), auditEvent.getType());

        final Map<String, Object> data = auditEvent.getData();
        WebAuthenticationDetails details = (WebAuthenticationDetails) data.get("details");
        if (details != null) {
            LOGGER.info("Remote IP address : {}", details.getRemoteAddress());
            LOGGER.info("Session Id : {}", details.getSessionId());
            LOGGER.info("Request URL : {}", data.get("requestUrl"));
        }
    }
}