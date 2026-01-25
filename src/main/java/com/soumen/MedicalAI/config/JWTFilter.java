package com.soumen.MedicalAI.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soumen.MedicalAI.service.CusUserDetailsService;
import com.soumen.MedicalAI.service.JWTService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class JWTFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JWTFilter.class);

    @Autowired
    private CusUserDetailsService userDetailsService;

    @Autowired
    private JWTService jwtService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        // Skip JWT validation for public endpoints
        String path = request.getServletPath();
        if (isPublicEndpoint(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");
        String token = null;
        String email = null;

        try {
            // Extract token from Authorization header
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                token = authHeader.substring(7).trim();
                email = jwtService.extractUsername(token);
            }

            // Validate and set authentication
            if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(email);

                if (jwtService.validateToken(token, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);

                    logger.debug("User '{}' authenticated successfully", email);
                } else {
                    logger.warn("Invalid JWT token for user: {}", email);
                }
            }

            filterChain.doFilter(request, response);

        } catch (ExpiredJwtException e) {
            logger.error("JWT token has expired: {}", e.getMessage());
            sendErrorResponse(response, "JWT token has expired", HttpServletResponse.SC_UNAUTHORIZED);
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token format: {}", e.getMessage());
            sendErrorResponse(response, "Invalid JWT token format", HttpServletResponse.SC_UNAUTHORIZED);
        } catch (SignatureException e) {
            logger.error("JWT signature validation failed: {}", e.getMessage());
            sendErrorResponse(response, "Invalid JWT signature", HttpServletResponse.SC_UNAUTHORIZED);
        } catch (UsernameNotFoundException e) {
            logger.error("User not found: {}", e.getMessage());
            sendErrorResponse(response, "User not found", HttpServletResponse.SC_UNAUTHORIZED);
        } catch (Exception e) {
            logger.error("JWT processing error: {}", e.getMessage(), e);
            sendErrorResponse(response, "Authentication error", HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    private boolean isPublicEndpoint(String path) {
        return path.equals("/api/med/user/signup") ||
                path.equals("/api/med/user/login") ||
                path.equals("/api/med/user/on-off") ||
                path.equals("/error");
    }

    private void sendErrorResponse(HttpServletResponse response, String message, int status) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("status", status);
        errorDetails.put("error", "Unauthorized");
        errorDetails.put("message", message);
        errorDetails.put("timestamp", System.currentTimeMillis());

        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getWriter(), errorDetails);
    }
}