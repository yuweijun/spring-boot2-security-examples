package com.example.spring.boot2.simple.security.web.util.matcher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;

public final class RegexRequestMatcher {

    private static final Logger LOGGER = LoggerFactory.getLogger(RegexRequestMatcher.class);

    private final Pattern pattern;

    private final HttpMethod httpMethod;

    public RegexRequestMatcher(String pattern, String httpMethod) {
        this(pattern, httpMethod, false);
    }

    public RegexRequestMatcher(String pattern, String httpMethod, boolean caseInsensitive) {
        if (caseInsensitive) {
            this.pattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        } else {
            this.pattern = Pattern.compile(pattern);
        }
        this.httpMethod = StringUtils.hasText(httpMethod) ? HttpMethod.valueOf(httpMethod) : null;
    }

    public boolean matches(HttpServletRequest request) {
        if (httpMethod != null && request.getMethod() != null && httpMethod != valueOf(request.getMethod())) {
            return false;
        }

        String url = request.getServletPath();
        String pathInfo = request.getPathInfo();
        String query = request.getQueryString();

        if (pathInfo != null || query != null) {
            StringBuilder sb = new StringBuilder(url);

            if (pathInfo != null) {
                sb.append(pathInfo);
            }

            if (query != null) {
                sb.append('?').append(query);
            }
            url = sb.toString();
        }

        LOGGER.debug("Checking match of request : '" + url + "'; against '" + pattern + "'");

        return pattern.matcher(url).matches();
    }

    private static HttpMethod valueOf(String method) {
        try {
            return HttpMethod.valueOf(method);
        } catch (IllegalArgumentException e) {
        }

        return null;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Regex [pattern='").append(this.pattern).append("'");

        if (this.httpMethod != null) {
            sb.append(", ").append(this.httpMethod);
        }

        sb.append("]");

        return sb.toString();
    }
}
