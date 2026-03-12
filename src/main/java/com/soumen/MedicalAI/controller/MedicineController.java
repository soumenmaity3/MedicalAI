package com.soumen.MedicalAI.controller;

import com.soumen.MedicalAI.Model.MedicineInd;
import com.soumen.MedicalAI.Model.users.Users;
import com.soumen.MedicalAI.Repository.MedicineRepo;
import com.soumen.MedicalAI.Repository.UserRepository;
import com.soumen.MedicalAI.config.Authorization;
import com.soumen.MedicalAI.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/medicine")
public class MedicineController {
    @Autowired
    private MedicineRepo repo;
    @Autowired
    private UserService service;
    @Autowired
    private Authorization authorization;
    @Autowired
    private UserRepository userRepo;

    @GetMapping("/all-medicines")
    public ResponseEntity<?> allMedicine(@RequestHeader("Authorization") String authHeader) {
        String token = authorization.token(authHeader);

        // Check if token extraction failed
        if (token.startsWith("Missing") || token.startsWith("Invalid")) {
            return new ResponseEntity<>(token, HttpStatus.UNAUTHORIZED);
        }

        String email = service.EmailFromToken(token);

        Users existingUser = userRepo.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        List<MedicineInd> medicines = repo.findAll();

        return new ResponseEntity<>(medicines, HttpStatus.OK);
    }

    @GetMapping("/search")
    public ResponseEntity<?> searchMedicine(
            @RequestHeader("Authorization") String authHeader,
            @RequestParam String name) {

        String token = authorization.token(authHeader);

        if (token.startsWith("Missing") || token.startsWith("Invalid")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(token);
        }

        String email = service.EmailFromToken(token);

        userRepo.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<MedicineInd> medicines = repo.fuzzySearch(name);

        return ResponseEntity.ok(medicines);
    }
}
