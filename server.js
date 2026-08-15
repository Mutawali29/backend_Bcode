require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Add these imports to server.js
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

// Koneksi ke Database MySQL (Aiven)
const db = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    ssl: {
        rejectUnauthorized: false
    },
    connectTimeout: 20000
});

console.log(process.env.DB_HOST);

// Simple verification code storage (in production, use a database)
const verificationCodes = new Map();

// TEST ENDPOINT - to check if your server is running properly
app.get("/api/test", async (req, res) => {
    try {
      const [rows] = await db.query("SELECT 1 as test");
      res.json({ message: "Server is running correctly!", dbConnected: true });
    } catch (err) {
      console.error("Error:", err);
      res.status(500).json({ message: "Server running, but DB connection failed" });
    }
  });

// SIMPLIFIED VERIFICATION ENDPOINT (for testing)
app.post("/api/send-verification", async (req, res) => {
    const { email, username } = req.body;
    
    try {
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        
        verificationCodes.set(email, {
            code: verificationCode,
            expires: Date.now() + 10 * 60 * 1000
        });
        
        console.log('Verification code for ${email}: ${verificationCode}');
        
        res.json({ 
            message: "Kode verifikasi telah dikirim",
            code: verificationCode 
        });
        
    } catch (err) {
        console.error("Error:", err);
        res.status(500).json({ message: "Terjadi kesalahan" });
    }
});

// REGISTER WITH VERIFICATION
app.post("/api/register", async (req, res) => {
    const { username, email, password, verificationCode } = req.body;

    try {
        const storedCode = verificationCodes.get(email);
        if (!storedCode || storedCode.code !== verificationCode) {
            return res.status(400).json({ 
                message: "Kode verifikasi salah", 
                field: "verification" 
            });
        }

        const [rows] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
        if (rows.length > 0) {
            return res.status(400).json({ message: "Username sudah digunakan!" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        const avatarUrl = 'https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=random';
        
        await db.query(
            "INSERT INTO users (username, email, password, avatar, is_verified) VALUES (?, ?, ?, ?, ?)", 
            [username, email, hashedPassword, avatarUrl, true]
        );
        
        verificationCodes.delete(email);
        
        res.json({ message: "Registrasi berhasil!" });
    } catch (err) {
        console.error("Error:", err);
        res.status(500).json({ message: "Terjadi kesalahan!", error: err.message });
    }
});

// LOGIN
app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        const [rows] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
        if (rows.length === 0) {
            return res.status(400).json({ message: "User tidak ditemukan!" });
        }

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Password salah!" });
        }

        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username,
                email: user.email,
                avatar: user.avatar || null,
                role: user.role || 'user'
            }, 
            process.env.SECRET_KEY, 
            { expiresIn: "1h" }
        );
        
        res.json({ 
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                avatar: user.avatar || null,
                role: user.role || 'user'
            }
        });
    } catch (err) {
        res.status(500).json({ message: "Terjadi kesalahan!", error: err.message });
    }
});

// MIDDLEWARE - Verifikasi Token
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ message: "Token diperlukan!" });

    jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ message: "Token tidak valid!" });
        req.user = decoded;
        next();
    });
};

// Configure multer for avatar uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      const uploadDir = 'uploads/avatars';
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      const ext = path.extname(file.originalname);
      cb(null, 'avatar-' + uniqueSuffix + ext);
    }
  });
  
  const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
      if (file.mimetype.startsWith('image/')) {
        cb(null, true);
      } else {
        cb(new Error('Only image files are allowed!'), false);
      }
    }
  });
  
  app.post("/api/update-profile", verifyToken, upload.single('avatar'), async (req, res) => {
    const { email, username } = req.body;
    const userId = req.user.id;
    
    try {
      if (username !== req.user.username) {
        const [usernameCheck] = await db.query(
          "SELECT id FROM users WHERE username = ? AND id != ?", 
          [username, userId]
        );
        
        if (usernameCheck.length > 0) {
          return res.status(400).json({ 
            success: false, 
            message: "Username sudah digunakan oleh pengguna lain!" 
          });
        }
      }
      
      if (email !== req.user.email) {
        const [emailCheck] = await db.query(
          "SELECT id FROM users WHERE email = ? AND id != ?", 
          [email, userId]
        );
        
        if (emailCheck.length > 0) {
          return res.status(400).json({ 
            success: false, 
            message: "Email sudah digunakan oleh pengguna lain!" 
          });
        }
      }
      
      let avatarPath = req.user.avatar;
      if (req.file) {
        const serverBaseUrl = process.env.SERVER_URL || 'http://127.0.0.1:8000';
        avatarPath = `${serverBaseUrl}/${req.file.path.replace(/\\/g, '/')}`;
      }
      
      await db.query(
        "UPDATE users SET username = ?, email = ?, avatar = ? WHERE id = ?",
        [username, email, avatarPath, userId]
      );
      
      const token = jwt.sign(
        {
          id: userId,
          username: username,
          email: email,
          avatar: avatarPath,
          role: req.user.role
        },
        process.env.SECRET_KEY,
        { expiresIn: "1h" }
      );
      
      res.json({ 
        success: true, 
        message: "Profil berhasil diperbarui",
        token,
        user: {
          id: userId,
          username: username,
          email: email,
          avatar: avatarPath,
          role: req.user.role
        }
      });
    } catch (err) {
      console.error("Error updating profile:", err);
      res.status(500).json({ 
        success: false, 
        message: "Terjadi kesalahan saat memperbarui profil!" 
      });
    }
  });
  
  app.use('/uploads', express.static('uploads'));

// Get user's coin balance
app.get("/api/coins", verifyToken, async (req, res) => {
    try {
        const [rows] = await db.query("SELECT coins FROM users WHERE id = ?", [req.user.id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: "User not found!" });
        }
        
        res.json({ coins: rows[0].coins });
    } catch (err) {
        res.status(500).json({ message: "Terjadi kesalahan!", error: err.message });
    }
});

// Use a coin (decrease by 1)
app.post("/api/use-coin", verifyToken, async (req, res) => {
    try {
        const [rows] = await db.query("SELECT coins FROM users WHERE id = ?", [req.user.id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: "User not found!" });
        }
        
        if (rows[0].coins <= 0) {
            return res.status(400).json({ message: "Koin tidak cukup!" });
        }
        
        await db.query("UPDATE users SET coins = coins - 1 WHERE id = ?", [req.user.id]);
        
        res.json({ message: "Koin berhasil digunakan", coins: rows[0].coins - 1 });
    } catch (err) {
        res.status(500).json({ message: "Terjadi kesalahan!", error: err.message });
    }
});

// Add coins (admin feature or for purchasing)
app.post("/api/add-coins", verifyToken, async (req, res) => {
    const { amount } = req.body;
    
    if (!amount || amount <= 0) {
        return res.status(400).json({ message: "Jumlah koin tidak valid!" });
    }
    
    try {
        await db.query("UPDATE users SET coins = coins + ? WHERE id = ?", [amount, req.user.id]);
        
        const [rows] = await db.query("SELECT coins FROM users WHERE id = ?", [req.user.id]);
        
        res.json({ message: "Koin berhasil ditambahkan", coins: rows[0].coins });
    } catch (err) {
        res.status(500).json({ message: "Terjadi kesalahan!", error: err.message });
    }
});

// MIDDLEWARE - Check if user is an admin
const isAdmin = async (req, res, next) => {
    try {
        const [rows] = await db.query("SELECT role FROM users WHERE id = ?", [req.user.id]);
        if (rows.length === 0 || rows[0].role !== 'admin') {
            return res.status(403).json({ message: "Akses ditolak! Hanya admin yang dapat mengakses." });
        }
        next();
    } catch (err) {
        res.status(500).json({ message: "Terjadi kesalahan!", error: err.message });
    }
};

// Get all users (admin only)
app.get("/api/admin/users", verifyToken, isAdmin, async (req, res) => {
    try {
        const [rows] = await db.query("SELECT id, username, email, coins, created_at FROM users");
        res.json(rows);
    } catch (err) {
        res.status(500).json({ message: "Terjadi kesalahan!", error: err.message });
    }
});

// Add coins to a user (admin only)
app.post("/api/admin/add-coins", verifyToken, isAdmin, async (req, res) => {
    const { userId, amount } = req.body;
    
    if (!userId || !amount || amount <= 0) {
        return res.status(400).json({ message: "ID pengguna dan jumlah koin diperlukan!" });
    }
    
    try {
        const [userRows] = await db.query("SELECT * FROM users WHERE id = ?", [userId]);
        if (userRows.length === 0) {
            return res.status(404).json({ message: "Pengguna tidak ditemukan!" });
        }
        
        await db.query("UPDATE users SET coins = coins + ? WHERE id = ?", [amount, userId]);
        
        const [updatedRows] = await db.query("SELECT coins FROM users WHERE id = ?", [userId]);
        
        await db.query(
            "INSERT INTO coin_transactions (user_id, admin_id, amount, transaction_type, description) VALUES (?, ?, ?, ?, ?)",
            [userId, req.user.id, amount, "admin_add", `Koin ditambahkan oleh admin ${req.user.username}`]
        );
        
        res.json({ 
            message: "Koin berhasil ditambahkan", 
            coins: updatedRows[0].coins 
        });
    } catch (err) {
        res.status(500).json({ message: "Terjadi kesalahan!", error: err.message });
    }
});

// ROUTE TERLINDUNGI - Dashboard
app.get("/api/dashboard", verifyToken, (req, res) => {
    res.json({ message: 'Selamat datang, ${req.user.username}!' });
});

// Jalankan Server
const PORT = process.env.PORT || 8000;

if (process.env.NODE_ENV == 'production') {
    app.listen(PORT, () => {
        console.log('Server berjalan di http://127.0.0.1:${PORT}');
        console.log('Available endpoints:');
        console.log('- GET /api/test');
        console.log('- POST /api/send-verification');
        console.log('- POST /api/register');
        console.log('- POST /api/login');
        console.log('- GET /api/dashboard [protected]');
    });
}

module.exports = app;