package com.soumen.MedicalAI.Repository;

import com.soumen.MedicalAI.Model.PredictionHistory;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PredictionHistoryRepository extends JpaRepository<PredictionHistory,Integer > {
}
