package com.example.spring.boot2.simple.security.web;

import com.example.spring.boot2.simple.security.web.authentication.filter.SecurityContextPersistenceFilter;
import com.example.spring.boot2.simple.security.web.authentication.filter.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author yuweijun 2022-06-25.
 */
public class FilterChainProxy extends GenericFilterBean {

    private UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter = new UsernamePasswordAuthenticationFilter();

    private SecurityContextPersistenceFilter securityContextPersistenceFilter = new SecurityContextPersistenceFilter();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        List<Filter> filters = getFilters();

        if (filters.size() == 0) {
            chain.doFilter(request, response);

            return;
        }

        VirtualFilterChain vfc = new VirtualFilterChain(chain, filters);
        vfc.doFilter(request, response);
    }

    private List<Filter> getFilters() {
        List<Filter> filters = new ArrayList<>();

        // securityContextPersistenceFilter must before usernamePasswordAuthenticationFilter
        filters.add(securityContextPersistenceFilter);
        filters.add(usernamePasswordAuthenticationFilter);
        return filters;
    }
}
