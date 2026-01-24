package com.soumen.MedicalAI.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
@Configuration
public class Authorization {

    public String token(String authHeader){
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return("Missing or invalid token");
        }

        String token = authHeader.substring(7).trim();
        if (token.contains(",")) {
            String[] parts = token.split(",");
            token = parts[parts.length - 1].replace("Bearer", "").trim();
        }
        return token;
    }
}

