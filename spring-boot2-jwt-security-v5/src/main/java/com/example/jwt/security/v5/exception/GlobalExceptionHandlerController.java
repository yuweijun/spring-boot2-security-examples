package com.example.jwt.security.v5.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestControllerAdvice
public class GlobalExceptionHandlerController {

    private static final Logger LOGGER = LoggerFactory.getLogger(GlobalExceptionHandlerController.class);

    @ExceptionHandler(CustomException.class)
    public void handleCustomException(HttpServletResponse response, CustomException customException) throws IOException {
        LOGGER.error("CustomException error", customException);
        response.sendError(customException.getHttpStatus().value(), customException.getMessage());
    }

    /**
     * <pre>
     * this exception handler AOP will intercept {@link org.springframework.security.access.AccessDeniedException}
     * and disable {@link RestfulAccessDeniedHandler} exception handler
     * </pre>
     */
    @ExceptionHandler(Exception.class)
    public void handleException(HttpServletResponse response, Exception e) throws IOException {
        int status = HttpStatus.BAD_REQUEST.value();
        LOGGER.error("@ExceptionHandler(Exception.class) in GlobalExceptionHandlerController", e);
        // Sends an error response to the client using the specified status code and clears the output buffer.
        if (e instanceof AccessDeniedException) {
          status = HttpStatus.FORBIDDEN.value();
        }
        response.sendError(status, "Something went wrong");
    }

}
