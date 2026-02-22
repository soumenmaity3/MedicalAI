package com.soumen.MedicalAI.controller;

import com.soumen.MedicalAI.Model.users.LoginUser;
import com.soumen.MedicalAI.Model.symptoms.SymptomRequest;
import com.soumen.MedicalAI.Model.users.Users;
import com.soumen.MedicalAI.Repository.UserRepository;
import com.soumen.MedicalAI.Repository.doctor.DoctorRepo;
import com.soumen.MedicalAI.config.Authorization;
import com.soumen.MedicalAI.config.FileEncryptionUtil;
import com.soumen.MedicalAI.dto.UserDTO;
import com.soumen.MedicalAI.service.HuggingFaceService;
import com.soumen.MedicalAI.service.JWTService;
import com.soumen.MedicalAI.service.UserService;
import com.soumen.MedicalAI.utils.PasswordValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

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
    private HuggingFaceService faceService;

    @Autowired
    private DoctorRepo doctorRepo;

    @Autowired
    Authorization authorization;

    @Autowired
    private PasswordEncoder encoder;

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
        String email = user.getEmail() != null ? user.getEmail().trim().toLowerCase() : null;
        System.out.println("Processing signup for email: [" + email + "]"); // Debug log

        if (email == null || email.isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Email is required");
                        }
                    });
        }

        // Check if user already exists in either table
        if (repo.existsByEmailIgnoreCase(email) || doctorRepo.existsByEmailIgnoreCase(email)) {
            System.out.println("Signup failed: Email [" + email + "] is already registered.");
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Email is already registered. Please login or use a different email.");
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
        String passwordError = PasswordValidator.validate(password);
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
            newUser.setEmail(email);
            newUser.setPassword(encoder.encode(user.getPassword()));
            newUser.setName(user.getName());

            // Save user to database
            Users savedUser = repo.save(newUser);

            // Create claims for JWT
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", "ROLE_USER");
            claims.put("userId", savedUser.getId().toString());

            // ✅ Generate tokens directly using normalized email from the saved user
            String token = jwtService.generateToken(claims, savedUser.getEmail());
            String refreshToken = jwtService.generateRefreshToken(savedUser.getEmail());

            // Create response with user data (without password)
            Map<String, Object> response = new HashMap<>();
            response.put("message", "User created and logged in successfully");
            response.put("user", UserDTO.from(savedUser));
            response.put("token", token);
            response.put("refreshToken", refreshToken);
            response.put("expiresIn", 86400000);

            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Signup error: " + e.getMessage());
                        }
                    });
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginUser login) {

        // Validate email
        String email = login.getEmail();
        if (email == null || email.isEmpty()) {
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

        String normalizedEmail = email.trim().toLowerCase();
        try {
            // Authenticate using Spring Security
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            normalizedEmail,
                            login.getPassword()));

            // Get user details
            Optional<Users> userOpt = repo.findByEmailIgnoreCase(normalizedEmail);
            if (userOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new HashMap<String, String>() {
                            {
                                put("error", "Access denied: This account is not registered as a Patient.");
                            }
                        });
            }

            Users user = userOpt.get();

            // Create claims for JWT
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", "ROLE_USER");
            claims.put("userId", user.getId().toString());

            // Generate tokens using normalized email
            String token = jwtService.generateToken(claims, user.getEmail());
            String refreshToken = jwtService.generateRefreshToken(user.getEmail());

            // Create standardized response
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Login successful");
            response.put("user", UserDTO.from(user));
            response.put("token", token);
            response.put("refreshToken", refreshToken);
            response.put("expiresIn", 86400000);

            return ResponseEntity.ok(response);

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Invalid email or password");
                        }
                    });
        } catch (DisabledException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Account is disabled");
                        }
                    });
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Login error: " + e.getMessage());
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
            Optional<Users> existUser = repo.findByEmailIgnoreCase(email);

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
            Optional<Users> existUser = repo.findByEmailIgnoreCase(email);

            if (existUser.isEmpty()) {
                return new ResponseEntity<>("User not found..", HttpStatus.NOT_FOUND);
            }

            return new ResponseEntity<>(existUser.get(), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("Error processing request: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @DeleteMapping("/me")
    public ResponseEntity<?> deleteCurrentUser(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = authorization.token(authHeader);

            if (token.startsWith("Missing") || token.startsWith("Invalid")) {
                return new ResponseEntity<>(token, HttpStatus.UNAUTHORIZED);
            }

            String email = service.EmailFromToken(token);
            Optional<Users> existUser = repo.findByEmailIgnoreCase(email);

            if (existUser.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            repo.delete(existUser.get());

            return new ResponseEntity<>("User account deleted successfully", HttpStatus.OK);

        } catch (Exception e) {
            return new ResponseEntity<>("Error deleting account: " + e.getMessage(),
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

            Users existingUser = repo.findByEmailIgnoreCase(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body("File is empty");
            }

            // 🔐 Encrypt image data and store directly in Database
            byte[] encryptedBytes = encryptionUtil.encrypt(file.getBytes());

            existingUser.setProfileImage(encryptedBytes);
            repo.save(existingUser);

            return ResponseEntity.ok("Profile image uploaded to database successfully");
        } catch (Exception e) {
            e.printStackTrace();
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

            Users user = repo.findByEmailIgnoreCase(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            if (user.getProfileImage() == null) {
                return ResponseEntity
                        .status(HttpStatus.NOT_FOUND)
                        .body("No profile image found in database");
            }

            // 🔐 3. Decrypt image data from database
            byte[] decryptedBytes = encryptionUtil.decrypt(user.getProfileImage());

            // 🖼️ 4. Return as image (default to jpeg as extension is lost)
            return ResponseEntity
                    .ok()
                    .contentType(MediaType.IMAGE_JPEG)
                    .body(decryptedBytes);

        } catch (Exception e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to load profile image from database: " + e.getMessage());
        }
    }

    @PostMapping("/predict")
    public ResponseEntity<?> symptomPredict(@RequestHeader("Authorization") String authHeader,
            @RequestBody SymptomRequest request) {
        String token = authorization.token(authHeader);

        if (token.startsWith("Missing") || token.startsWith("Invalid")) {
            return new ResponseEntity<>(token, HttpStatus.UNAUTHORIZED);
        }

        String email = service.EmailFromToken(token);
        Optional<Users> existUser = repo.findByEmailIgnoreCase(email);

        if (existUser.isEmpty()) {
            return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
        }

        String text = request.getText();

        return ResponseEntity.ok(faceService.getPrediction(text));
    }

    @DeleteMapping("/deleteAll")
    public ResponseEntity<?> deleteAll(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = authorization.token(authHeader);

            if (token.startsWith("Missing") || token.startsWith("Invalid")) {
                return new ResponseEntity<>(token, HttpStatus.UNAUTHORIZED);
            }

            String email = service.EmailFromToken(token);
            // Check in both repositories to see if user exists
            boolean userExists = repo.existsByEmailIgnoreCase(email) || doctorRepo.existsByEmailIgnoreCase(email);

            if (!userExists) {
                return new ResponseEntity<>("Authorized user not found in database", HttpStatus.NOT_FOUND);
            }

            faceService.deleteAll();
            return ResponseEntity.ok(new HashMap<String, String>() {
                {
                    put("message", "All prediction history deleted successfully");
                }
            });
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error clearing history: " + e.getMessage());
        }
    }

    @PostMapping("/update-profile")
    public ResponseEntity<?> updateProfile(@RequestHeader("Authorization") String authHeader,
            @RequestBody Users userUpdate) {
        try {
            String token = authorization.token(authHeader);

            if (token.startsWith("Missing") || token.startsWith("Invalid")) {
                return new ResponseEntity<>(token, HttpStatus.UNAUTHORIZED);
            }

            String email = service.EmailFromToken(token);
            Optional<Users> userOpt = repo.findByEmailIgnoreCase(email);

            if (userOpt.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            Users existingUser = userOpt.get();

            // Update only permitted fields
            if (userUpdate.getName() != null)
                existingUser.setName(userUpdate.getName());
            if (userUpdate.getDob() != null)
                existingUser.setDob(userUpdate.getDob());
            if (userUpdate.getBlood() != null)
                existingUser.setBlood(userUpdate.getBlood());
            if (userUpdate.getGender() != null)
                existingUser.setGender(userUpdate.getGender());
            if (userUpdate.getWeight() != null)
                existingUser.setWeight(userUpdate.getWeight());
            if (userUpdate.getHeight() != null)
                existingUser.setHeight(userUpdate.getHeight());
            if (userUpdate.getExercise() != null)
                existingUser.setExercise(userUpdate.getExercise());
            if (userUpdate.getDiet() != null)
                existingUser.setDiet(userUpdate.getDiet());
            if (userUpdate.getAllergies() != null)
                existingUser.setAllergies(userUpdate.getAllergies());
            if (userUpdate.getPastSurgeries() != null)
                existingUser.setPastSurgeries(userUpdate.getPastSurgeries());

            // Save the updated entity
            repo.save(existingUser);

            Map<String, Object> response = new HashMap<>();
            response.put("message", "Profile updated successfully");
            response.put("user", UserDTO.from(existingUser));

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error updating profile: " + e.getMessage());
        }
    }

}
