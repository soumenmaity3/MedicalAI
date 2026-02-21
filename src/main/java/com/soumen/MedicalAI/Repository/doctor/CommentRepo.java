package com.soumen.MedicalAI.Repository.doctor;

import com.soumen.MedicalAI.Model.doctor.Comments;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface CommentRepo extends JpaRepository<Comments, UUID> {
}
