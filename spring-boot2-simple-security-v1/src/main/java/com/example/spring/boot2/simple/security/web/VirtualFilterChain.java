package com.example.spring.boot2.simple.security.web;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * @author yuweijun 2022-06-25.
 */
public class VirtualFilterChain implements FilterChain {

    private final FilterChain originalChain;

    private final List<? extends Filter> additionalFilters;

    private int currentPosition = 0;

    public VirtualFilterChain(FilterChain chain, List<? extends Filter> additionalFilters) {
        this.originalChain = chain;
        this.additionalFilters = additionalFilters;
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response) throws IOException, ServletException {
        if (this.currentPosition == this.additionalFilters.size()) {
            this.originalChain.doFilter(request, response);
        } else {
            this.currentPosition++;
            Filter nextFilter = this.additionalFilters.get(this.currentPosition - 1);
            nextFilter.doFilter(request, response, this);
        }
    }
}
