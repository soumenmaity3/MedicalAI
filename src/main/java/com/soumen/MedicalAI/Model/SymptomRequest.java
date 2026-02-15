package com.soumen.MedicalAI.Model;

public class SymptomRequest {
    private  String text;

    public SymptomRequest(String text) {
        this.text = text;
    }

    public SymptomRequest() {
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }
}
