package com.soumen.MedicalAI.controller;

import com.soumen.MedicalAI.Model.doctor.Doctor;
import com.soumen.MedicalAI.Model.doctor.LoginDoctor;
import com.soumen.MedicalAI.Model.doctor.Specialization;
import com.soumen.MedicalAI.Repository.doctor.DoctorDTO;
import com.soumen.MedicalAI.Repository.doctor.DoctorRepo;
import org.springframework.security.authentication.*;
import com.soumen.MedicalAI.service.JWTService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/med/doc")
public class DoctorController {

    @Autowired
    private DoctorRepo repo;
    @Autowired
    private com.soumen.MedicalAI.Repository.UserRepository userRepo;
    @Autowired
    private JWTService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private PasswordEncoder encoder;

    @GetMapping("/on-off")
    public ResponseEntity<?> serverOnOff() {
        return new ResponseEntity<>(true, HttpStatus.OK);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody Doctor doctor) {
        // valid email
        String email = doctor.getEmail() != null ? doctor.getEmail().trim().toLowerCase() : null;
        if (email == null || email.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Email is required");
                        }
                    });
        }
        // valid name
        String name = doctor.getFull_name() != null ? doctor.getFull_name().trim() : null;
        if (name == null || name.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Name is required");
                        }
                    });
        }
        // valid license
        String license_no = doctor.getLicense_no() != null ? doctor.getLicense_no().trim() : null;
        if (license_no == null || license_no.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "License Number is required");
                        }
                    });
        }
        // valid specialization
        Specialization specialization = doctor.getSpecialization() != null ? doctor.getSpecialization() : null;
        if (specialization == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Specialization is required");
                        }
                    });
        }
        // valid year exp
        int year_exp = doctor.getExperience() != 0 ? doctor.getExperience() : 0;
        if (year_exp == 0) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Experience is required");
                        }
                    });
        }
        // valid clinic name
        String clinic_name = doctor.getClinic_name() != null ? doctor.getClinic_name().trim() : null;
        if (clinic_name == null || clinic_name.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Clinic Name is required");
                        }
                    });
        }
        // check user already exist in either table
        if (repo.existsByEmailIgnoreCase(email) || userRepo.existsByEmailIgnoreCase(email)) {
            System.out.println("Signup failed: Email [" + email + "] is already used.");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Email already in use. Try another one.");
                        }
                    });
        }
        // valid password
        String password = doctor.getPassword();
        if (password == null || password.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Password is required");
                        }
                    });
        }
        try {
            // Create new doctor
            Doctor doctor1 = new Doctor();
            doctor1.setEmail(email);
            doctor1.setPassword(encoder.encode(doctor.getPassword()));
            doctor1.setFull_name(doctor.getFull_name());
            doctor1.setClinic_name(doctor.getClinic_name());
            doctor1.setExperience(doctor.getExperience());
            doctor1.setSpecialization(doctor.getSpecialization());
            doctor1.setNo_of_patients(doctor.getNo_of_patients());
            doctor1.setLicense_no(doctor.getLicense_no());

            Doctor saveDoctor = repo.save(doctor1);

            // Create claims for JWT
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", "ROLE_DOCTOR");
            claims.put("userId", saveDoctor.getId().toString());

            String token = jwtService.generateToken(claims, saveDoctor.getEmail());
            String refreshToken = jwtService.generateRefreshToken(saveDoctor.getEmail());

            Map<String, Object> response = new HashMap<>();
            response.put("message", "Doctor created and logged in successfully");
            response.put("user", DoctorDTO.from(saveDoctor));
            response.put("token", token);
            response.put("refreshToken", refreshToken);
            response.put("expiresIn", 86400000);

            return ResponseEntity.status(HttpStatus.OK).body(response);

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
    public ResponseEntity<?> login(@RequestBody LoginDoctor doctor) {
        // valid email
        String email = doctor.getEmail();
        if (email == null || email.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Email is required");
                        }
                    });
        }
        String normalizedEmail = email != null ? email.trim().toLowerCase() : "";
        String password = doctor.getPassword();
        if (password == null || password.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new HashMap<String, String>() {
                        {
                            put("error", "Password is required");
                        }
                    });
        }
        try {
            System.out.println("Attempting doctor login for: [" + normalizedEmail + "]");
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            normalizedEmail,
                            doctor.getPassword()));

            // Safety check: Ensure the authenticated user is actually a Doctor
            Optional<Doctor> doctorOpt = repo.findByEmailIgnoreCase(normalizedEmail);
            if (doctorOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new HashMap<String, String>() {
                            {
                                put("error", "Access denied: This account is not registered as a Doctor.");
                            }
                        });
            }

            Doctor doctor1 = doctorOpt.get();

            // Create claims for JWT
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", "ROLE_DOCTOR");
            claims.put("userId", doctor1.getId().toString());

            String token = jwtService.generateToken(claims, doctor1.getEmail());
            String refreshToken = jwtService.generateRefreshToken(doctor1.getEmail());

            Map<String, Object> response = new HashMap<>();
            response.put("message", "Login successful");
            response.put("user", DoctorDTO.from(doctor1));
            response.put("token", token);
            response.put("refreshToken", refreshToken);
            response.put("expiresIn", 86400000);

            return ResponseEntity.status(HttpStatus.OK).body(response);

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

}
