const express = require("express");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const cors = require("cors");

dotenv.config();

const app = express();
app.use(express.json());

// CORS Yapılandırması (Tüm domainlere izin vermek için app.use(cors()))
const corsOptions = {
    origin: "http://localhost:3000", // Sadece belirli bir frontend erişebilecek (Değiştirebilirsin)
    methods: "GET,POST",
    allowedHeaders: "Content-Type,Authorization",
};
app.use(cors(corsOptions));

const SECRET_KEY = process.env.SECRET_KEY || "secret";
const PORT = process.env.PORT || 4000; // PORT'u .env'den al, yoksa 4000 kullan

// RATE LIMITING: 15 dakika içinde en fazla 5 istek
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 5, // Maksimum 5 istek
    message: { message: "Too many requests, please try again later." },
});

// Kullanıcıya JWT token oluşturma fonksiyonu
function createToken(user) {
    return jwt.sign({ user }, SECRET_KEY, { expiresIn: "1h" }); // 1 saat süresi olan token
}

// Token oluşturma endpoint'i (POST metodu kullanıyoruz)
app.post(
    "/token",
    limiter, // Rate Limit Middleware
    [
        body("username")
            .trim()
            .notEmpty().withMessage("Username is required")
            .isLength({ min: 3 }).withMessage("Username must be at least 3 characters long"),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username } = req.body;
        const token = createToken(username);
        res.json({ access_token: token });
    }
);

// Kimlik doğrulama middleware'i
function authenticate(req, res, next) {
    console.log("Authorization Header:", req.headers.authorization);
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Unauthorized: No token provided" });
    }

    const token = authHeader.split(" ")[1]; // "Bearer <TOKEN>" formatından alıyoruz
    console.log("Extracted Token:", token);

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            console.log("JWT Verify Error:", err.message);
            return res.status(401).json({ message: "Invalid or expired token" });
        }

        req.user = decoded.user;
        next();
    });
}

// Güvenli endpoint
app.get("/secure-data", authenticate, (req, res) => {
    res.json({ message: `Hello, ${req.user}!` });
});

// Sunucuyu başlat
app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
