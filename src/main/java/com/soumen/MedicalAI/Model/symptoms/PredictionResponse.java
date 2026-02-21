package com.soumen.MedicalAI.Model.symptoms;

import java.util.List;

public class PredictionResponse {

    private String input_text;
    private List<DepartmentPrediction> top_predictions;
    private DepartmentPrediction final_prediction;

    public static class DepartmentPrediction {
        private String department;
        private double confidence;

        public String getDepartment() { return department; }
        public void setDepartment(String department) { this.department = department; }

        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }
    }

    public String getInput_text() { return input_text; }
    public void setInput_text(String input_text) { this.input_text = input_text; }

    public List<DepartmentPrediction> getTop_predictions() { return top_predictions; }
    public void setTop_predictions(List<DepartmentPrediction> top_predictions) { this.top_predictions = top_predictions; }

    public DepartmentPrediction getFinal_prediction() { return final_prediction; }
    public void setFinal_prediction(DepartmentPrediction final_prediction) { this.final_prediction = final_prediction; }
}

