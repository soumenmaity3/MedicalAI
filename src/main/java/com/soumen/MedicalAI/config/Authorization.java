package com.soumen.MedicalAI.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Configuration
public class Authorization {

    /**
     * Extract JWT token from Authorization header
     * FIXED: Removed unnecessary comma handling that could cause issues
     *
     * @param authHeader The Authorization header value
     * @return The extracted token or error message
     */
    public String token(String authHeader){
        if (authHeader == null || authHeader.isBlank()) {
            return "Missing or invalid token";
        }

        if (!authHeader.startsWith("Bearer ")) {
            return "Invalid token format";
        }

        // Extract token after "Bearer "
        String token = authHeader.substring(7).trim();

        if (token.isEmpty()) {
            return "Empty token";
        }

        return token;
    }
}