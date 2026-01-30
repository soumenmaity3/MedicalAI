package com.soumen.MedicalAI.controller;

import com.soumen.MedicalAI.Model.LoginUser;
import com.soumen.MedicalAI.Model.Users;
import com.soumen.MedicalAI.Repository.UserRepository;
import com.soumen.MedicalAI.config.Authorization;
import com.soumen.MedicalAI.config.FileEncryptionUtil;
import com.soumen.MedicalAI.service.JWTService;
import com.soumen.MedicalAI.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@RestController
@CrossOrigin("*")
@RequestMapping("/api/med/user")
public class UserController {
    @Autowired
    private UserRepository repo;

    @Autowired
    private UserService service;

    @Autowired
    Authorization authorization;

    @Autowired
    private BCryptPasswordEncoder encoder;

    @Autowired
    JWTService jwtService;

    @Autowired
    FileEncryptionUtil encryptionUtil;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/on-off")
    public ResponseEntity<?> serverOnOff() {
        return new ResponseEntity<>(true, HttpStatus.OK);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody Users user) {

        // Validate email
        String email = user.getEmail();
        if (email == null || email.isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Email is required");
                        }
                    });
        }

        // Check if user already exists
        if (repo.existsByEmail(email)) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "User already exists. Please login.");
                        }
                    });
        }

        // Validate password
        String password = user.getPassword();
        if (password == null || password.isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Password is required");
                        }
                    });
        }

        // Validate password strength
        String passwordError = com.soumen.MedicalAI.utils.PasswordValidator.validate(password);
        if (passwordError != null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", passwordError);
                        }
                    });
        }

        // Validate name
        String name = user.getName();
        if (name == null || name.isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Name is required");
                        }
                    });
        }

        try {
            // Create new user
            Users newUser = new Users();
            newUser.setEmail(user.getEmail());
            newUser.setPassword(encoder.encode(user.getPassword()));
            newUser.setName(user.getName());

            // Save user to database
            Users savedUser = repo.save(newUser);

            // ✅ PROPERLY authenticate the user after signup
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            user.getEmail(),
                            user.getPassword() // Use original plain text password
                    ));

            // Generate tokens AFTER successful authentication
            String token = jwtService.generateToken(user.getEmail());
            String refreshToken = jwtService.generateRefreshToken(user.getEmail());

            // Create response with user data (without password)
            Map<String, Object> response = new HashMap<>();
            response.put("message", "User created and logged in successfully");
            response.put("user", com.soumen.MedicalAI.dto.UserDTO.from(savedUser));
            response.put("token", token);
            response.put("refreshToken", refreshToken);
            response.put("expiresIn", 86400000);

            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "An error occurred during signup: " + e.getMessage());
                        }
                    });
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginUser login) {

        // Validate email
        if (login.getEmail() == null || login.getEmail().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Email is required");
                        }
                    });
        }

        // Validate password
        if (login.getPassword() == null || login.getPassword().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Password is required");
                        }
                    });
        }

        try {
            // Authenticate using Spring Security
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            login.getEmail(),
                            login.getPassword()));

            // Get user details
            Users user = repo.findByEmail(login.getEmail())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Generate tokens
            String token = jwtService.generateToken(login.getEmail());
            String refreshToken = jwtService.generateRefreshToken(login.getEmail());

            // Create standardized response
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Login successful");
            response.put("user", com.soumen.MedicalAI.dto.UserDTO.from(user));
            response.put("token", token);
            response.put("refreshToken", refreshToken);
            response.put("expiresIn", 86400000);

            return ResponseEntity.ok(response);

        } catch (org.springframework.security.authentication.BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Invalid email or password");
                        }
                    });
        } catch (org.springframework.security.authentication.DisabledException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Account is disabled");
                        }
                    });
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "An error occurred during login");
                        }
                    });
        }
    }

    @GetMapping("/me/{id}")
    private ResponseEntity<?> myDetails(@RequestHeader("Authorization") String authHeader,
            @PathVariable("id") UUID userId) {
        try {
            String token = authorization.token(authHeader);

            // Check if token extraction failed
            if (token.startsWith("Missing") || token.startsWith("Invalid")) {
                return new ResponseEntity<>(token, HttpStatus.UNAUTHORIZED);
            }

            String email = service.EmailFromToken(token);
            Optional<Users> existUser = repo.findByEmail(email);

            if (existUser.isEmpty()) {
                return new ResponseEntity<>("User not found..", HttpStatus.NOT_FOUND);
            }

            // FIXED: This was checking if IDs are equal and returning NOT_FOUND
            // Should check if IDs are NOT equal
            if (!existUser.get().getId().equals(userId)) {
                return new ResponseEntity<>("User not found..", HttpStatus.NOT_FOUND);
            }

            return new ResponseEntity<>(existUser.get(), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("Error processing request: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/me")
    private ResponseEntity<?> myDetails(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = authorization.token(authHeader);

            // Check if token extraction failed
            if (token.startsWith("Missing") || token.startsWith("Invalid")) {
                return new ResponseEntity<>(token, HttpStatus.UNAUTHORIZED);
            }

            String email = service.EmailFromToken(token);
            Optional<Users> existUser = repo.findByEmail(email);

            if (existUser.isEmpty()) {
                return new ResponseEntity<>("User not found..", HttpStatus.NOT_FOUND);
            }

            return new ResponseEntity<>(existUser.get(), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("Error processing request: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @DeleteMapping("/{id}/user-delete")
    public ResponseEntity<?> deleteUser(@RequestHeader("Authorization") String authHeader,
            @PathVariable("id") UUID userId) {
        try {
            String token = authorization.token(authHeader);

            // Check if token extraction failed
            if (token.startsWith("Missing") || token.startsWith("Invalid")) {
                return new ResponseEntity<>(token, HttpStatus.UNAUTHORIZED);
            }

            String email = service.EmailFromToken(token);
            Optional<Users> existUser = repo.findByEmail(email);

            if (existUser.isEmpty()) {
                return new ResponseEntity<>("User not found..", HttpStatus.NOT_FOUND);
            }

            if (existUser.get().getId().equals(userId)) {
                repo.deleteById(userId);
                return new ResponseEntity<>("User delete success..", HttpStatus.ACCEPTED);
            } else {
                return new ResponseEntity<>("User are not allow to delete..", HttpStatus.NOT_ACCEPTABLE);
            }
        } catch (Exception e) {
            return new ResponseEntity<>("Error processing request: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/{id}/upload-profile")
    public ResponseEntity<?> uploadProfileImage(
            @RequestHeader("Authorization") String authHeader,
            @RequestParam("file") MultipartFile file) {
        try {
            String token = authorization.token(authHeader);

            // Check if token extraction failed
            if (token.startsWith("Missing") || token.startsWith("Invalid")) {
                return new ResponseEntity<>(token, HttpStatus.UNAUTHORIZED);
            }

            String email = service.EmailFromToken(token);

            Users existingUser = repo.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            Path uploadPath = Paths.get("profile_images");
            Files.createDirectories(uploadPath);

            String fileName = existingUser.getEmail() + ".enc";
            Path filePath = uploadPath.resolve(fileName);

            byte[] encryptedBytes = encryptionUtil.encrypt(file.getBytes());
            Files.write(filePath, encryptedBytes);

            existingUser.setProfileImage(fileName);
            repo.save(existingUser);

            return ResponseEntity.ok("Encrypted profile image uploaded");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error uploading profile image: " + e.getMessage());
        }
    }

    @GetMapping("/profile-image/me")
    public ResponseEntity<?> getMyProfileImage(
            @RequestHeader("Authorization") String authHeader) {
        try {
            // 🔐 1. Extract & validate token
            String token = authorization.token(authHeader);

            if (token.startsWith("Missing") || token.startsWith("Invalid")) {
                return ResponseEntity
                        .status(HttpStatus.UNAUTHORIZED)
                        .body("Invalid or missing token");
            }

            // 🔐 2. Identify user from token
            String email = service.EmailFromToken(token);

            Users user = repo.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            if (user.getProfileImage() == null) {
                return ResponseEntity
                        .status(HttpStatus.NOT_FOUND)
                        .body("No profile image");
            }

            // 📁 3. Resolve file safely
            Path imagePath = Paths.get("profile_images")
                    .resolve(user.getProfileImage())
                    .normalize()
                    .toAbsolutePath();

            if (!Files.exists(imagePath)) {
                return ResponseEntity
                        .status(HttpStatus.NOT_FOUND)
                        .body("Image file not found");
            }

            // 🔐 4. Decrypt image
            byte[] encryptedBytes = Files.readAllBytes(imagePath);
            byte[] decryptedBytes = encryptionUtil.decrypt(encryptedBytes);

            // 🖼️ 5. Detect content type
            String contentType = Files.probeContentType(imagePath);
            MediaType mediaType = contentType != null
                    ? MediaType.parseMediaType(contentType)
                    : MediaType.APPLICATION_OCTET_STREAM;

            return ResponseEntity
                    .ok()
                    .contentType(mediaType)
                    .body(decryptedBytes);

        } catch (Exception e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to load profile image");
        }
    }

}
