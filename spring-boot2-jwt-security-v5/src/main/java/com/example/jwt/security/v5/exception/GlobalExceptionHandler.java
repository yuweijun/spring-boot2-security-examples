package com.example.jwt.security.v5.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AccessDeniedException.class)
    public void handleAccessDeniedException(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            LOGGER.error("AccessDenied for user : {}", auth.getName());
        }

        LOGGER.error("AccessDenied for request : {}", request.getRequestURI());
        response.sendError(HttpStatus.FORBIDDEN.value());
    }

    @ExceptionHandler(CustomException.class)
    public void handleCustomException(HttpServletResponse response, CustomException e) throws IOException {
        LOGGER.error("CustomException error", e);
        response.sendError(e.getHttpStatus().value());
    }

    @ExceptionHandler(Exception.class)
    public void handleException(HttpServletResponse response, Exception e) throws IOException {
        LOGGER.error("@ExceptionHandler(Exception.class) in GlobalExceptionHandlerController", e);
        response.sendError(HttpStatus.BAD_REQUEST.value());
    }

}
