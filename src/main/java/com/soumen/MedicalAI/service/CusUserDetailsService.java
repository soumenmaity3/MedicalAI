package com.soumen.MedicalAI.service;

import com.soumen.MedicalAI.Model.doctor.Doctor;
import com.soumen.MedicalAI.Model.users.Users;
import com.soumen.MedicalAI.Repository.UserRepository;
import com.soumen.MedicalAI.Repository.doctor.DoctorRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

@Service
public class CusUserDetailsService implements UserDetailsService {

        @Autowired
        private UserRepository userRepository;

        @Autowired
        private DoctorRepo doctorRepo;

        @Override
        public UserDetails loadUserByUsername(String email)
                        throws UsernameNotFoundException {

                String normalizedEmail = email != null ? email.trim().toLowerCase() : "";

                // Try to find in Doctors
                Optional<Doctor> doctor = doctorRepo.findByEmailIgnoreCase(normalizedEmail);
                if (doctor.isPresent()) {
                        System.out.println("Authentication Success: Found email [" + normalizedEmail
                                        + "] in Doctors table.");
                        return new org.springframework.security.core.userdetails.User(
                                        doctor.get().getEmail(),
                                        doctor.get().getPassword(),
                                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_DOCTOR")));
                }

                // Try to find in Users
                Optional<Users> user = userRepository.findByEmailIgnoreCase(normalizedEmail);
                if (user.isPresent()) {
                        System.out.println("Authentication Success: Found email [" + normalizedEmail
                                        + "] in Users table.");
                        return new org.springframework.security.core.userdetails.User(
                                        user.get().getEmail(),
                                        user.get().getPassword(),
                                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
                }

                System.out.println("Authentication Failed: Email [" + normalizedEmail + "] not found in any table.");
                throw new UsernameNotFoundException("User or Doctor not found with email: " + normalizedEmail);
        }
}