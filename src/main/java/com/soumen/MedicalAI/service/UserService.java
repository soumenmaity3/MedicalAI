package com.soumen.MedicalAI.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private JWTService service;
    @Autowired
    private AuthenticationManager manager;
    public String verify(String email,String password){
        try{
            Authentication authentication =
                    manager.authenticate(new UsernamePasswordAuthenticationToken(email,password));
            if(authentication.isAuthenticated()){
                return service.generateToken(email);
            }
            return "fail";
        }catch (Exception e){
            return "fail";
        }
    }
    public String EmailFromToken(String token){
        try {
            return service.extractUsername(token);
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }
}
