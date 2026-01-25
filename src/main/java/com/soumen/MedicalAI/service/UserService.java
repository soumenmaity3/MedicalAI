package com.soumen.MedicalAI.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private JWTService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * Verify user credentials and generate JWT token
     */
    public String verify(String email, String password) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)
            );

            if (authentication.isAuthenticated()) {
                logger.info("User authenticated successfully: {}", email);
                return jwtService.generateToken(email);
            }

            logger.warn("Authentication failed for user: {}", email);
            throw new BadCredentialsException("Invalid credentials");

        } catch (DisabledException e) {
            logger.error("User account is disabled: {}", email);
            throw new RuntimeException("User account is disabled");
        } catch (BadCredentialsException e) {
            logger.error("Invalid credentials for user: {}", email);
            throw new RuntimeException("Invalid email or password");
        } catch (AuthenticationException e) {
            logger.error("Authentication error for user {}: {}", email, e.getMessage());
            throw new RuntimeException("Authentication failed: " + e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error during authentication for user {}: {}", email, e.getMessage(), e);
            throw new RuntimeException("An unexpected error occurred during authentication");
        }
    }

    /**
     * Extract email from JWT token
     */
    public String getEmailFromToken(String token) {
        try {
            return jwtService.extractUsername(token);
        } catch (Exception e) {
            logger.error("Error extracting email from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Generate refresh token
     */
    public String generateRefreshToken(String email) {
        return jwtService.generateRefreshToken(email);
    }

    /**
     * Validate token
     */
    public boolean validateToken(String token) {
        try {
            String email = jwtService.extractUsername(token);
            return email != null && !jwtService.extractExpiration(token).before(new java.util.Date());
        } catch (Exception e) {
            logger.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }
}