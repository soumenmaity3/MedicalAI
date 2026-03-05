package com.soumen.MedicalAI.lang_chain_ai.controller;

import com.soumen.MedicalAI.Model.users.Users;
import com.soumen.MedicalAI.Repository.UserRepository;
import com.soumen.MedicalAI.config.Authorization;
import com.soumen.MedicalAI.lang_chain_ai.service.ChatService;
import com.soumen.MedicalAI.service.UserService;
import org.apache.tika.Tika;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Optional;

@RestController
@RequestMapping("/api/file")
public class FileController {
    @Autowired
    Authorization authorization;

    @Autowired
    private UserService service;

    @Autowired
    private UserRepository repo;

    private final ChatService chatService;

    public FileController(ChatService chatService) {
        this.chatService = chatService;
    }

    // @PostMapping("/analyze")
    // public ResponseEntity<?> analyzeFile(@RequestHeader("Authorization") String
    // authHeader, @RequestParam("file") MultipartFile file) throws Exception {
    //
    // String token = authorization.token(authHeader);
    //
    // if (token.startsWith("Missing") || token.startsWith("Invalid")) {
    // return new ResponseEntity<>(token, HttpStatus.UNAUTHORIZED);
    // }
    //
    // String email = service.EmailFromToken(token);
    // Optional<Users> userOpt = repo.findByEmailIgnoreCase(email);
    //
    // if (userOpt.isEmpty()) {
    // return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
    // }
    //
    // String text = FileTextExtractor.extractText(file);
    //
    // String prompt = "Analyze this file content:\n" + text;
    //
    // String reply= chatService.chat(prompt);
    //
    // return new ResponseEntity<>(reply, HttpStatus.OK);
    // }

    @PostMapping("/analyze")
    public ResponseEntity<?> analyze(@RequestHeader("Authorization") String authHeader,
            @RequestParam("file") MultipartFile file,
            @RequestParam("prompt") String prompt,
            @RequestParam(value = "model", required = false) String model) throws Exception {

        String token = authorization.token(authHeader);

        if (token.startsWith("Missing") || token.startsWith("Invalid")) {
            return new ResponseEntity<>(token, HttpStatus.UNAUTHORIZED);
        }

        String email = service.EmailFromToken(token);
        Optional<Users> userOpt = repo.findByEmailIgnoreCase(email);

        if (userOpt.isEmpty()) {
            return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
        }

        String text = FileTextExtractor.extractText(file);

        if (text == null || text.trim().isEmpty()) {
            return new ResponseEntity<>("I received the file '" + file.getOriginalFilename()
                    + "', but I couldn't extract any readable text from it. Please try uploading a PDF, Word document, or a plain text file. (Images are not currently supported for text analysis).",
                    HttpStatus.OK);
        }

        String reply = chatService.analyzeFile(text, prompt);
        return new ResponseEntity<>(reply, HttpStatus.OK);
    }

    public class FileTextExtractor {

        public static String extractText(MultipartFile file) throws Exception {

            Tika tika = new Tika();

            String text = tika.parseToString(file.getInputStream());
            System.out.println(text);

            return text;
        }
    }
}
