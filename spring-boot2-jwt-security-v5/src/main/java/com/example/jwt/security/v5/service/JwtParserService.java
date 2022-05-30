package com.example.jwt.security.v5.service;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;

public class JwtParserService {

    public JwtParser getParser() {
        return Jwts.parser();
    }

}
