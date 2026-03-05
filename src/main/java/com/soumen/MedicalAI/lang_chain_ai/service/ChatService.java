package com.soumen.MedicalAI.lang_chain_ai.service;

import dev.langchain4j.model.openai.OpenAiChatModel;
import org.springframework.stereotype.Service;

import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.UserMessage;

@Service
public class ChatService {

        private final OpenAiChatModel chatModel;

        public ChatService(OpenAiChatModel chatModel) {
                this.chatModel = chatModel;
        }

        public String chat(String message) {

                SystemMessage systemMessage = SystemMessage.from(
                                """
                                                Act as a senior medical professional with years of clinical experience.
                                                Explain medical information clearly.
                                                Do not provide unsafe medical advice.
                                                If uncertain, say the information is limited.
                                                """);

                UserMessage userMessage = UserMessage.from(message);

                return chatModel.generate(systemMessage, userMessage)
                                .content()
                                .text();
        }

        public String analyzeFile(String fileContent, String userPrompt) {

                SystemMessage systemMessage = SystemMessage.from("""
                                Act as a highly experienced medical professional.
                                Carefully analyze the provided document.
                                Explain medical terms clearly.
                                Answer the user's question based only on the document.
                                If the document does not contain the answer, say that the information is not available.
                                """);

                UserMessage userMessage = UserMessage.from("""
                                USER PROMPT:
                                %s

                                FILE CONTENT:
                                %s
                                """.formatted(userPrompt, fileContent));

                return chatModel.generate(systemMessage, userMessage)
                                .content()
                                .text();
        }

        private String getModelId(String requestedModel) {
                if (requestedModel == null)
                        return "llama-3.1-70b-versatile";

                String lower = requestedModel.toLowerCase();
                if (lower.contains("llama"))
                        return "llama-3.1-70b-versatile";
                if (lower.contains("mixtral"))
                        return "mixtral-8x7b-32768";
                if (lower.contains("gemma"))
                        return "gemma-7b-it";

                // Default for others if we don't have specialized keys yet
                return "llama-3.1-70b-versatile";
        }
}