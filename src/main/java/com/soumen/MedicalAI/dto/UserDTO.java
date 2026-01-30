package com.soumen.MedicalAI.dto;

import com.soumen.MedicalAI.Model.Users;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;
import java.util.UUID;

/**
 * Data Transfer Object for User information
 * Excludes sensitive data like passwords
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {
    private UUID id;
    private String email;
    private String name;
    private LocalDate dob;
    private String blood;
    private String gender;
    private Integer weight;
    private Integer height;
    private String exercise;
    private String diet;
    private String allergies;
    private String pastSurgeries;
    private String profileImage;

    /**
     * Convert Users entity to UserDTO
     * 
     * @param user The user entity
     * @return UserDTO without password
     */
    public static UserDTO from(Users user) {
        if (user == null) {
            return null;
        }

        UserDTO dto = new UserDTO();
        dto.setId(user.getId());
        dto.setEmail(user.getEmail());
        dto.setName(user.getName());
        dto.setDob(user.getDob());
        dto.setBlood(user.getBlood() != null ? user.getBlood().toString() : null);
        dto.setGender(user.getGender() != null ? user.getGender().toString() : null);
        dto.setWeight(user.getWeight());
        dto.setHeight(user.getHeight());
        dto.setExercise(user.getExercise() != null ? user.getExercise().toString() : null);
        dto.setDiet(user.getDiet() != null ? user.getDiet().toString() : null);
        dto.setAllergies(user.getAllergies());
        dto.setPastSurgeries(user.getPast_surgeries());
        dto.setProfileImage(user.getProfileImage());

        return dto;
    }
}
