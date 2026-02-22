package com.soumen.MedicalAI.service;

import com.soumen.MedicalAI.Model.symptoms.PredictionHistory;
import com.soumen.MedicalAI.Model.symptoms.PredictionResponse;
import com.soumen.MedicalAI.Model.symptoms.SymptomRequest;
import com.soumen.MedicalAI.Repository.PredictionHistoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.Set;

@Service
public class HuggingFaceService {

        @Autowired
        private PredictionHistoryRepository repository;

        private String HF_API_URL = "https://sm89-symptom2disease-api.hf.space/predict";

        private static final Set<String> MEDICAL_KEYWORDS = Set.of(
                        "fever", "cough", "pain", "headache", "nausea", "vomiting", "fatigue", "dizziness",
                        "shortness of breath", "chest pain", "abdominal pain", "diarrhea", "constipation",
                        "rash", "swelling", "itching", "sore throat", "runny nose", "congestion",
                        "muscle ache", "joint pain", "blurred vision", "seizure", "insomnia",
                        "anxiety", "depression", "heart", "lung", "liver", "kidney", "stomach",
                        "brain", "blood", "sugar", "pressure", "diabetes", "hypertension", "infection",
                        "flu", "cold", "allergy", "asthma", "cancer", "tumor", "fracture", "injury",
                        "symptom", "disease", "medicine", "treatment", "doctor", "hospital", "clinic");

        public PredictionResponse getPrediction(String text) {
                RestTemplate restTemplate = new RestTemplate();
                SymptomRequest request = new SymptomRequest(text);

                HttpHeaders headers = new HttpHeaders();

                headers.setContentType(MediaType.APPLICATION_JSON);

                HttpEntity<SymptomRequest> entity = new HttpEntity<>(request, headers);
                ResponseEntity<PredictionResponse> response = restTemplate.exchange(HF_API_URL,
                                HttpMethod.POST,
                                entity,
                                PredictionResponse.class);
                PredictionResponse prediction = response.getBody();

                // 🔥 Save to DB only if it contains medical words
                if (prediction != null && prediction.getFinal_prediction() != null) {
                        if (containsMedicalWord(text)) {
                                String department = prediction.getFinal_prediction().getDepartment();
                                double confidence = prediction.getFinal_prediction().getConfidence();

                                PredictionHistory history = new PredictionHistory(text, department, confidence);
                                repository.save(history);
                                System.out.println("History saved for: " + text);
                        } else {
                                System.out.println("History skipped (No medical words detected): " + text);
                        }
                }
                return prediction;
        }

        private boolean containsMedicalWord(String text) {
                if (text == null || text.isBlank())
                        return false;
                String lowerText = text.toLowerCase();
                return MEDICAL_KEYWORDS.stream().anyMatch(lowerText::contains);
        }

    public void deleteAll() {
            repository.deleteAll();
    }
}
