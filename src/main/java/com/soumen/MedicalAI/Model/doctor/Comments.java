package com.soumen.MedicalAI.Model.doctor;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.soumen.MedicalAI.Model.users.Users;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class Comments {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @NotNull
    private String comment;

    private long rating;

    @OneToOne
    @JoinColumn(name = "user_id")
    @JsonIgnore
    private Users user;
    @ManyToOne
    @JoinColumn(name = "doctor_id")
    @JsonIgnore
    private Doctor doctor;
}
