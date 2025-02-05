# User Registration Microservice - .NET Core

## 📌 Overview
This microservice provides user authentication and registration functionality using **ASP.NET Core Identity** with **JWT-based authentication**. It supports:
✅ User Registration & Login
✅ JWT Authentication
✅ Two-Factor Authentication (2FA)
✅ Social Media Login (Google, Facebook, etc.)
✅ Authenticator App Integration

## 🚀 Technologies Used
- **.NET 8** (ASP.NET Core Web API)
- **Entity Framework Core** (EF Core)
- **Microsoft Identity**
- **JWT (JSON Web Token)**
- **SQL Server**
- **Postman (for testing API)**
- **Swagger UI**

## 📂 Project Structure
```
/UserRegistrationMicroservice
│── Controllers
│   ├── AuthController.cs   # Handles User Authentication & JWT Token Generation
│   ├── TestController.cs   # Sample Protected API Endpoint
│── Data
│   ├── ApplicationDbContext.cs # Database Context with Identity
│── Models
│   ├── RegisterModel.cs    # DTO for User Registration
│   ├── LoginModel.cs       # DTO for User Login
│── appsettings.json        # Configuration (JWT, DB Connection)
│── Program.cs              # Application Entry & Configuration
│── README.md               # Project Documentation
```

## ⚙️ Setup Instructions

### 1️⃣ Clone the Repository
```sh
git clone https://github.com/your-repo/user-registration-microservice.git
cd user-registration-microservice
```

### 2️⃣ Install Dependencies
```sh
dotnet restore
```

### 3️⃣ Configure Database Connection
Edit **`appsettings.json`**:
```json
"ConnectionStrings": {
  "DefaultConnection": "Server=localhost;Database=UserDb;User Id=sa;Password=YourPassword;"
},
"Jwt": {
  "SecretKey": "YourStrongSecretKey",
  "Issuer": "https://localhost:5001",
  "Audience": "https://yourfrontend.com"
}
```

### 4️⃣ Run Database Migrations
```sh
dotnet ef migrations add InitialCreate
dotnet ef database update
```

### 5️⃣ Run the Application
```sh
dotnet run
```
The API will be available at **`https://localhost:5001`**

### 6️⃣ Test with Postman / Swagger
#### ✅ **Register a User**
- **Endpoint:** `POST /api/auth/register`
- **Body:**
```json
{
  "email": "testuser@example.com",
  "password": "Test@12345"
}
```

#### ✅ **Login to Get JWT Token**
- **Endpoint:** `POST /api/auth/login`
- **Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiration": "2025-02-06T10:30:00Z"
}
```

#### ✅ **Access a Protected API**
- **Endpoint:** `GET /api/test/protected`
- **Headers:**
  - `Authorization: Bearer <your-token>`
- **Response:**
```json
"This is a protected API!"
```

## 🔒 Security Best Practices
- **Use Environment Variables** for JWT Secrets instead of hardcoding.
- **Enable HTTPS** in production.
- **Implement Rate Limiting** to prevent brute-force attacks.
- **Use Refresh Tokens** for improved security.

## 🛠 Future Enhancements
- ✅ Google & Facebook OAuth Login
- ✅ Two-Factor Authentication (2FA) with Authenticator Apps
- ✅ Email Confirmation & Password Reset

## 📜 License
This project is licensed under the MIT License.

---
🎯 **Happy Coding!** 🚀

