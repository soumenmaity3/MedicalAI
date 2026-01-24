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
    public ResponseEntity<?> serverOnOff(){
        return new ResponseEntity<>(true,HttpStatus.OK);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody Users user){

        String email = user.getEmail();
        if(email == null || email.isBlank()){
            return new ResponseEntity<>("Email is required..", HttpStatus.NOT_ACCEPTABLE);
        }

        Optional<Users> userEmail = repo.existByEmail(email);
        if (userEmail.isPresent()){
            return new ResponseEntity<>("User Already Exist. Please Login..", HttpStatus.CONFLICT);
        }

        String password = user.getPassword();
        if(password == null || password.isBlank()){
            return new ResponseEntity<>("Password is required..", HttpStatus.NOT_ACCEPTABLE);
        }

        String name = user.getName();
        if(name == null || name.isBlank()){
            return new ResponseEntity<>("Name is required..", HttpStatus.NOT_ACCEPTABLE);
        }

        Users newUser = new Users();
        newUser.setEmail(user.getEmail());
        newUser.setPassword(encoder.encode(user.getPassword()));
        newUser.setName(user.getName());
        System.out.printf(user.getPassword());
        System.out.printf(user.getEmail());

        Users saveUser=repo.save(newUser);

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

        // 🔴 Authenticate using Spring Security
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        login.getEmail(),
                        login.getPassword()
                )
        );

        // ✅ If authentication fails → exception thrown automatically

        // ✅ Generate token ONLY after authentication
        String token = jwtService.generateToken(login.getEmail());

        return ResponseEntity.ok(token);
    }

    @GetMapping("/me")
    private ResponseEntity<?> myDetails(@RequestHeader("Authorization") String authHeader){
        String token = authorization.token(authHeader);
        try {
            String email = service.EmailFromToken(token);
            Optional<Users> existUser = repo.existByEmail(email);
            if (existUser.isEmpty()) {
                return new ResponseEntity<>("User not found..", HttpStatus.NOT_FOUND);
            }
            return new ResponseEntity<>(existUser.get(), HttpStatus.OK);
        } catch (Exception e) {
                throw new RuntimeException(e);
        }
    }

    @PostMapping("/{id}/upload-profile")
    public ResponseEntity<?> uploadProfileImage(
            @RequestHeader("Authorization") String authHeader,
            @RequestParam("file") MultipartFile file
    ) throws Exception {

        String token = authorization.token(authHeader);
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
    }

    @GetMapping("/profile-image/{id}")
    public ResponseEntity<byte[]> getProfileImage(@PathVariable UUID id) throws Exception {

        Users user = repo.findById(id).orElseThrow();

        Path path = Paths.get("profile_images").resolve(user.getProfileImage());
        byte[] encrypted = Files.readAllBytes(path);

        byte[] decrypted = encryptionUtil.decrypt(encrypted);

        return ResponseEntity.ok()
                .contentType(MediaType.IMAGE_JPEG)
                .body(decrypted);
    }

}
//http://localhost:8080/api/users/{id}/upload-profile - return this for upload
//String imageUrl = "http://localhost:8080/uploads/" + user.getProfileImage(); - return images