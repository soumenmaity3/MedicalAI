package com.soumen.MedicalAI.service;

import com.soumen.MedicalAI.Model.Users;
import com.soumen.MedicalAI.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CusUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository repo;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user = repo.findByEmail(username);
        if(user == null){
            throw new UsernameNotFoundException("User not find");
        }
        return User.builder()
                .username(user.getEmail())
                .password(user.getPassword())
                .authorities("ROLE_USER")
                .build();
    }

    public UserDetails loadUserByEmail(String username) throws UsernameNotFoundException {
        Users user = repo.findByEmail(username);
        if(user == null){
            throw new UsernameNotFoundException("User not find");
        }
        return User.builder()
                .username(user.getEmail())
                .password(user.getPassword())
                .authorities("ROLE_USER")
                .build();
    }
}
