# Web API Development and Security (Lab #2)

## Objective
This lab teaches students how to create a simple **RESTful API**, implement **JWT authentication**, and apply **basic security measures** to protect the API.

## Expected Outcome
By the end of this lab, you will have:
- Created a **RESTful API** using **Express.js (Node.js)**.
- Implemented **JWT authentication** for secure access.
- Applied **basic security measures** like CORS, Rate Limiting, and HTTPS enforcement.

## Prerequisites
Before starting, ensure you have:
- **Node.js (v14+)** installed.
- **Postman** or **curl** for API testing.
- Basic knowledge of **HTTP methods (GET, POST, PUT, DELETE)**.

## Project Setup
### 1. Initialize Node.js Project
```sh
mkdir api_lab2 && cd api_lab2
npm init -y
```

### 2. Install Required Dependencies
```sh
npm install express jsonwebtoken dotenv cors express-rate-limit
```

## Creating the RESTful API
### 1. Create `server.js` File
```javascript
const express = require("express");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = process.env.SECRET_KEY || "secret";
const PORT = process.env.PORT || 4000;

// Rate Limiting
const limiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
});
app.use("/token", limiter);

// Function to Create JWT Token
function createToken(user) {
    return jwt.sign({ user }, SECRET_KEY, { expiresIn: "1h" });
}

// Token Generation Endpoint
app.post("/token", (req, res) => {
    const { username } = req.body;
    if (!username) {
        return res.status(400).json({ message: "Username is required" });
    }
    const token = createToken(username);
    res.json({ access_token: token });
});

// Middleware for Authentication
function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Unauthorized: No token provided" });
    }
    const token = authHeader.split(" ")[1];
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: "Invalid or expired token" });
        }
        req.user = decoded.user;
        next();
    });
}

// Secure Endpoint
app.get("/secure-data", authenticate, (req, res) => {
    res.json({ message: `Hello, ${req.user}!` });
});

// Start Server
app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
```

### 2. Create a `.env` File (Environment Variables)
```env
SECRET_KEY=mySuperSecretKey
```

## Running the API
Start the API with:
```sh
node server.js
```

## Testing the API
### 1. Generate a Token
Use **Postman** or **cURL** to send a `POST` request:
```sh
curl -X POST http://localhost:4000/token -H "Content-Type: application/json" -d '{"username": "testuser"}'
```
#### Response:
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### 2. Access Secure Data
Copy the **access token** and send a `GET` request with it:
```sh
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:4000/secure-data
```
#### Response:
```json
{
    "message": "Hello, testuser!"
}
```

## Security Enhancements
### 1. Rate Limiting
- Limits repeated requests to `/token` endpoint to **5 requests per 10 minutes**.
- Protects against **brute force attacks**.

### 2. CORS (Cross-Origin Resource Sharing)
- Allows **frontend applications** to access the API.

### 3. Environment Variables
- **SECRET_KEY** is stored in `.env` to **prevent exposure in code**.

### 4. HTTPS Enforcement (Recommended for Production)
- Use **SSL Certificates** to encrypt API communication.
- Deploy API on **HTTPS-enabled servers**.

## Questions & Answers
### 1. What is a RESTful API?
A **RESTful API** follows REST principles: stateless communication, resource-based URLs, and standard HTTP methods.

### 2. Main HTTP Methods in REST API:
- **GET** → Retrieve data
- **POST** → Create data
- **PUT** → Update data
- **DELETE** → Remove data

### 3. Benefits of JSON Format:
- Lightweight & human-readable.
- Faster parsing than XML.
- Language-independent.

### 4. Role of Middleware:
- Handles **authentication, logging, security (CORS, rate limiting)**.

### 5. What is JWT?
JWT is a **secure token format** used for **authentication**.

### 6. How does JWT ensure security?
- **Digitally signed** to prevent tampering.
- Includes **expiration time**.

### 7. Three Parts of JWT:
1. **Header** – Metadata (Algorithm, Type)
2. **Payload** – Encoded User Info
3. **Signature** – Verifies Token Integrity

### 8. How an API Verifies JWT:
- **Decodes JWT** and checks the signature.

### 9. Session-based vs. Token-based Authentication:
| Feature | Session-Based | Token-Based |
|---------|--------------|------------|
| **Storage** | Stored on server | Stored on client |
| **Scalability** | Harder to scale | Easy to scale |

### 10. API Security Threats:
- **SQL Injection** → Use prepared statements.
- **XSS** → Sanitize input.
- **Brute Force Attacks** → Rate limiting.

### 11. What is CORS?
CORS controls **which domains** can access an API.

### 12. How to Prevent Brute Force Attacks?
- **Rate limiting**
- **Account lockout**

### 13. Importance of Rate Limiting:
- Prevents **abuse & DoS attacks**.

### 14. Best Practices for Storing Secret Keys:
- **Use `.env` file** instead of hardcoding.

### 15. How HTTPS Improves Security:
- Encrypts communication to **prevent eavesdropping**.

## Conclusion
This lab successfully implemented a **JWT-secured RESTful API** with **Express.js**, **rate limiting**, **CORS**, and **security best practices**.

🚀 **Happy coding!**

