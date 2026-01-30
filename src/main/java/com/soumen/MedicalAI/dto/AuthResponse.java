package com.soumen.MedicalAI.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Response DTO for authentication endpoints (login/signup)
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String message;
    private UserDTO user;
    private String token;
    private String refreshToken;
    private Long expiresIn;

    /**
     * Constructor for response with token only
     */
    public AuthResponse(String message, UserDTO user, String token) {
        this.message = message;
        this.user = user;
        this.token = token;
        this.expiresIn = 86400000L; // 24 hours
    }
}
