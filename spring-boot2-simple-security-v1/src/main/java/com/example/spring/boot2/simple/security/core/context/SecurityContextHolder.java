package com.example.spring.boot2.simple.security.core.context;

public class SecurityContextHolder {

    private static ThreadLocalSecurityContextHolderStrategy strategy = new ThreadLocalSecurityContextHolderStrategy();

    public static void clearContext() {
        strategy.clearContext();
    }

    public static SecurityContext getContext() {
        return strategy.getContext();
    }

    public static void setContext(SecurityContext context) {
        strategy.setContext(context);
    }

    public static SecurityContext createEmptyContext() {
        return strategy.createEmptyContext();
    }

}
