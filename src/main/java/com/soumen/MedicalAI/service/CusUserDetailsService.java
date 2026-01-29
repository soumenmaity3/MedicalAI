package com.soumen.MedicalAI.service;

import com.soumen.MedicalAI.Model.Users;
import com.soumen.MedicalAI.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;

@Service
public class CusUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email)
            throws UsernameNotFoundException {

        Users user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new UsernameNotFoundException(
                                "User not found with email: " + email
                        )
                );

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),       // IMPORTANT
                user.getPassword(),    // MUST be encoded
                Collections.emptyList()
        );
    }


    /**
     * Get user authorities/roles
     * You can extend this to support multiple roles from your Users entity
     */
    private Collection<? extends GrantedAuthority> getAuthorities(Users user) {
        // If you have a roles field in Users entity, map it here
        // For now, returning a default role
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));

        // Example for multiple roles:
        // return user.getRoles().stream()
        //     .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
        //     .collect(Collectors.toList());
    }
}