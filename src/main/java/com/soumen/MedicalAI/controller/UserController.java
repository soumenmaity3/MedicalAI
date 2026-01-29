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

        String email = user.getEmail();
        if (email == null || email.isBlank()) {
            return new ResponseEntity<>("Email is required..", HttpStatus.NOT_ACCEPTABLE);
        }

        Optional<Users> userEmail = repo.existByEmail(email);
        if (userEmail.isPresent()) {
            return new ResponseEntity<>("User Already Exist. Please Login..", HttpStatus.CONFLICT);
        }

        String password = user.getPassword();
        if (password == null || password.isBlank()) {
            return new ResponseEntity<>("Password is required..", HttpStatus.NOT_ACCEPTABLE);
        }

        String name = user.getName();
        if (name == null || name.isBlank()) {
            return new ResponseEntity<>("Name is required..", HttpStatus.NOT_ACCEPTABLE);
        }

        Users newUser = new Users();
        newUser.setEmail(user.getEmail());
        newUser.setPassword(encoder.encode(user.getPassword()));
        newUser.setName(user.getName());
        System.out.printf(user.getPassword());
        System.out.printf(user.getEmail());

        Users saveUser = repo.save(newUser);

        String token = jwtService.generateToken(user.getEmail());

        Map<String, Object> response = new HashMap<>();
        response.put("user", saveUser);
        response.put("token", token);


        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginUser login) {

        if (login.getEmail() == null || login.getEmail().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Email is required");
        }

        if (login.getPassword() == null || login.getPassword().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Password is required");
        }

        try {
            // Authenticate using Spring Security
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            login.getEmail(),
                            login.getPassword()
                    )
            );

            // Generate token ONLY after authentication
            String token = jwtService.generateToken(login.getEmail());

            return ResponseEntity.ok(token);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid email or password");
        }
    }

    @GetMapping("/me/{id}")
    private ResponseEntity<?> myDetails(@RequestHeader("Authorization") String authHeader, @PathVariable("id") UUID userId) {
        try {
            String token = authorization.token(authHeader);

            // Check if token extraction failed
            if (token.startsWith("Missing") || token.startsWith("Invalid")) {
                return new ResponseEntity<>(token, HttpStatus.UNAUTHORIZED);
            }

            String email = service.EmailFromToken(token);
            Optional<Users> existUser = repo.existByEmail(email);

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
            return new ResponseEntity<>("Error processing request: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
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
            Optional<Users> existUser = repo.existByEmail(email);

            if (existUser.isEmpty()) {
                return new ResponseEntity<>("User not found..", HttpStatus.NOT_FOUND);
            }

            return new ResponseEntity<>(existUser.get(), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("Error processing request: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @DeleteMapping("/{id}/user-delete")
    public ResponseEntity<?> deleteUser(@RequestHeader("Authorization") String authHeader, @PathVariable("id") UUID userId) {
        try {
            String token = authorization.token(authHeader);

            // Check if token extraction failed
            if (token.startsWith("Missing") || token.startsWith("Invalid")) {
                return new ResponseEntity<>(token, HttpStatus.UNAUTHORIZED);
            }

            String email = service.EmailFromToken(token);
            Optional<Users> existUser = repo.existByEmail(email);

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
            return new ResponseEntity<>("Error processing request: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @PostMapping("/{id}/upload-profile")
    public ResponseEntity<?> uploadProfileImage(
            @RequestHeader("Authorization") String authHeader,
            @RequestParam("file") MultipartFile file
    ) {
        try {
            String token = authorization.token(authHeader);

            // Check if token extraction failed
            if (token.startsWith("Missing") || token.startsWith("Invalid")) {
                return new ResponseEntity<>(token, HttpStatus.UNAUTHORIZED);
            }

            String email = service.EmailFromToken(token);

            Users existingUser = repo.existByEmail(email)
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
            @RequestHeader("Authorization") String authHeader
    ) {
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

            Users user = repo.existByEmail(email)
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