# MedicalAI - AI-Powered Healthcare Platform

MedicalAI is a modern, full-stack medical assistance platform built with **Spring Boot** and **Java 21**. It leverages **Machine Learning** to help patients identify potential health issues based on their symptoms and connects them with the right medical departments.

## 🚀 Features

- **AI Symptom Checker**: Integrates with a custom Hugging Face ML model to predict diseases and suggest medical departments based on user-input symptoms.
- **Secure Authentication**: Robust JWT-based authentication system for both Patients and Doctors.
- **Role-Based Access**: Specialized functionality and repositories for Patients and Doctors.
- **Profile Management**: Profile picture upload support with secure storage.
- **Interactive Documentation**: Fully documented REST APIs using Swagger/OpenAPI.
- **Cloud Ready**: Containerized with Docker and configured for seamless deployment on platforms like Render.

## 🛠️ Tech Stack

- **Framework**: Spring Boot 3.4.x (Java 21)
- **Security**: Spring Security + JWT (JSON Web Token)
- **Database**: PostgreSQL
- **Persistence**: Spring Data JPA / Hibernate
- **AI Integration**: Hugging Face Inference API
- **Documentation**: Springdoc OpenAPI (Swagger UI)
- **Build Tool**: Maven
- **Containerization**: Docker

## 📋 API Documentation

Once the application is running, you can access the interactive Swagger UI at:
`http://localhost:8080/swagger-ui/index.html`

## ⚙️ Configuration

The application requires the following environment variables for production (Render/Cloud):

| Variable | Description |
| :--- | :--- |
| `JDBC_DATABASE_URL` | PostgreSQL JDBC Connection URL |
| `JDBC_DATABASE_USERNAME` | Database Username |
| `JDBC_DATABASE_PASSWORD` | Database Password |
| `JWT_SECRET` | Base64 encoded secret key for JWT signing |
| `PORT` | Server port (defaults to 8080) |

## 🛠️ Installation & Setup

### Local Setup
1. **Clone the repository**:
   ```bash
   git clone https://github.com/soumenmaity3/MedicalAI.git
   cd MedicalAI
   ```

2. **Database Setup**:
   - Ensure PostgreSQL is running.
   - Create a database named `soumen` (or update `application.properties`).

3. **Configure Environment**:
   Update `src/main/resources/application.properties` with your local credentials.

4. **Build and Run**:
   ```bash
   mvn clean install
   mvn spring-boot:run
   ```

### Docker Setup
```bash
docker build -t medical-ai .
docker run -p 8080:8080 -e PORT=8080 medical-ai
```

## 📂 Project Structure

- `com.soumen.MedicalAI.controller`: REST Controllers for User and Doctor actions.
- `com.soumen.MedicalAI.service`: Business logic, including AI model interaction.
- `com.soumen.MedicalAI.Model`: Entity models for Users, Doctors, and Symptoms.
- `com.soumen.MedicalAI.config`: Security and JWT configurations.
- `com.soumen.MedicalAI.Repository`: Data access layer.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License.
