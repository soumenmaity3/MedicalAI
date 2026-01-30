package com.soumen.MedicalAI.Model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.time.LocalDate;
import java.util.UUID;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Table(name = "med_users")
public class Users {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Email
    @NotNull
    @Column(nullable = false, unique = true)
    private String email;

    @NotNull
    @Column(nullable = false)
    private String password;

    @NotNull
    @Column(nullable = false)
    private String name;

    private LocalDate dob;

    @Enumerated(EnumType.STRING)
    private BloodGroup blood;

    @Enumerated(EnumType.STRING)
    private Gender gender;

    private Integer weight;
    private Integer height;

    @Enumerated(EnumType.STRING)
    private ExerciseFrequency exercise;

    @Enumerated(EnumType.STRING)
    private Diet diet;

    private String allergies;
    private String pastSurgeries;

    @Lob
    @Column(nullable = true, columnDefinition = "BYTEA")
    private byte[] profileImage;
}
