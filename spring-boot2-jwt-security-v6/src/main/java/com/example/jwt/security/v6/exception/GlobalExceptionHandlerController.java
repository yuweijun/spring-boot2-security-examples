package com.example.jwt.security.v6.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

}
