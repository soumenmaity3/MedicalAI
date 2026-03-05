package com.soumen.MedicalAI.lang_chain_ai.controller;

import com.soumen.MedicalAI.Model.users.Users;
import com.soumen.MedicalAI.Repository.UserRepository;
import com.soumen.MedicalAI.config.Authorization;
import com.soumen.MedicalAI.lang_chain_ai.service.ChatService;
import com.soumen.MedicalAI.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api")
public class ChatController {

    @Autowired
    Authorization authorization;

    @Autowired
    private UserService service;

    @Autowired
    private UserRepository repo;

    private final ChatService chatService;

    public ChatController(ChatService chatService) {
        this.chatService = chatService;
    }

    @PostMapping("chat")
    public ResponseEntity<?> chat(@RequestHeader("Authorization") String authHeader,
            @RequestHeader(value = "X-Model", required = false) String model,
            @RequestBody String message) {
        String token = authorization.token(authHeader);

        if (token.startsWith("Missing") || token.startsWith("Invalid")) {
            return new ResponseEntity<>(token, HttpStatus.UNAUTHORIZED);
        }

        String email = service.EmailFromToken(token);
        Optional<Users> userOpt = repo.findByEmailIgnoreCase(email);

        if (userOpt.isEmpty()) {
            return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
        }
        String reply = chatService.chat(message);

        return new ResponseEntity<>(reply, HttpStatus.OK);
    }
}
