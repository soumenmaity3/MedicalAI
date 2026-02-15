package com.soumen.MedicalAI.service;

import com.soumen.MedicalAI.Model.PredictionHistory;
import com.soumen.MedicalAI.Model.PredictionResponse;
import com.soumen.MedicalAI.Model.SymptomRequest;
import com.soumen.MedicalAI.Repository.PredictionHistoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;


import java.net.http.*;

@Service
public class HuggingFaceService {

    @Autowired
    private PredictionHistoryRepository repository;

    private String HF_API_URL = "https://sm89-symptom2disease-api.hf.space/predict";

    public PredictionResponse getPrediction(String text){
        RestTemplate restTemplate = new RestTemplate();
        SymptomRequest request = new SymptomRequest(text);

        HttpHeaders headers = new HttpHeaders();

        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<SymptomRequest> entity = new HttpEntity<>(request,headers);
        ResponseEntity<PredictionResponse> response =
                restTemplate.exchange(HF_API_URL,
                        HttpMethod.POST,
                        entity,
                        PredictionResponse.class);
        PredictionResponse prediction = response.getBody();

        // 🔥 Save to DB
        if (prediction != null && prediction.getFinal_prediction() != null) {

            String department =
                    prediction.getFinal_prediction().getDepartment();

            double confidence =
                    prediction.getFinal_prediction().getConfidence();

            PredictionHistory history =
                    new PredictionHistory(text, department, confidence);

            repository.save(history);
        }
        return prediction;
    }
}
