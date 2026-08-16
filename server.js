require("dotenv").config();
const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");

const app = express();
app.use(cors());
app.use(express.json());

// Koneksi ke Supabase (Postgres via REST). service_role key = bypass RLS,
// AMAN dipakai di sini karena ini backend server, bukan kode yang jalan di browser.
// Jangan pernah kirim SUPABASE_SERVICE_ROLE_KEY ke frontend!
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Simple verification code storage (in production, use a database)
const verificationCodes = new Map();

// TEST ENDPOINT - to check if your server is running properly
app.get("/api/test", async (req, res) => {
  try {
    const { error } = await supabase.from("users").select("id").limit(1);
    if (error) throw error;
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
      expires: Date.now() + 10 * 60 * 1000,
    });

    console.log(`Verification code for ${email}: ${verificationCode}`);

    res.json({
      message: "Kode verifikasi telah dikirim",
      code: verificationCode,
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
        field: "verification",
      });
    }

    const { data: existingUsers, error: checkError } = await supabase
      .from("users")
      .select("id")
      .eq("username", username);

    if (checkError) throw checkError;
    if (existingUsers.length > 0) {
      return res.status(400).json({ message: "Username sudah digunakan!" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    // FIX: sebelumnya pakai single quote jadi ${username} nggak pernah ke-interpolate
    const avatarUrl = `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=random`;

    const { error: insertError } = await supabase.from("users").insert({
      username,
      email,
      password: hashedPassword,
      avatar: avatarUrl,
      is_verified: true,
    });

    if (insertError) throw insertError;

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
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("username", username)
      .single();

    if (error || !user) {
      return res.status(400).json({ message: "User tidak ditemukan!" });
    }

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
        role: user.role || "user",
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
        role: user.role || "user",
      },
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

// Multer pakai memory storage (BUKAN disk) karena filesystem Vercel
// read-only/ephemeral. File di-buffer di memori lalu diupload ke Supabase Storage.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed!"), false);
    }
  },
});

app.post("/api/update-profile", verifyToken, upload.single("avatar"), async (req, res) => {
  const { email, username } = req.body;
  const userId = req.user.id;

  try {
    if (username !== req.user.username) {
      const { data: usernameCheck, error: usernameErr } = await supabase
        .from("users")
        .select("id")
        .eq("username", username)
        .neq("id", userId);

      if (usernameErr) throw usernameErr;
      if (usernameCheck.length > 0) {
        return res.status(400).json({
          success: false,
          message: "Username sudah digunakan oleh pengguna lain!",
        });
      }
    }

    if (email !== req.user.email) {
      const { data: emailCheck, error: emailErr } = await supabase
        .from("users")
        .select("id")
        .eq("email", email)
        .neq("id", userId);

      if (emailErr) throw emailErr;
      if (emailCheck.length > 0) {
        return res.status(400).json({
          success: false,
          message: "Email sudah digunakan oleh pengguna lain!",
        });
      }
    }

    let avatarPath = req.user.avatar;
    if (req.file) {
      const ext = req.file.originalname.split(".").pop();
      const fileName = `avatar-${userId}-${Date.now()}.${ext}`;

      const { error: uploadError } = await supabase.storage
        .from("avatars")
        .upload(fileName, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: true,
        });

      if (uploadError) throw uploadError;

      const { data: publicUrlData } = supabase.storage
        .from("avatars")
        .getPublicUrl(fileName);

      avatarPath = publicUrlData.publicUrl;
    }

    const { error: updateError } = await supabase
      .from("users")
      .update({ username, email, avatar: avatarPath })
      .eq("id", userId);

    if (updateError) throw updateError;

    const token = jwt.sign(
      {
        id: userId,
        username,
        email,
        avatar: avatarPath,
        role: req.user.role,
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
        username,
        email,
        avatar: avatarPath,
        role: req.user.role,
      },
    });
  } catch (err) {
    console.error("Error updating profile:", err);
    res.status(500).json({
      success: false,
      message: "Terjadi kesalahan saat memperbarui profil!",
    });
  }
});

// Get user's coin balance
app.get("/api/coins", verifyToken, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("coins")
      .eq("id", req.user.id)
      .single();

    if (error || !user) {
      return res.status(404).json({ message: "User not found!" });
    }

    res.json({ coins: user.coins });
  } catch (err) {
    res.status(500).json({ message: "Terjadi kesalahan!", error: err.message });
  }
});

// Use a coin (decrease by 1)
app.post("/api/use-coin", verifyToken, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("coins")
      .eq("id", req.user.id)
      .single();

    if (error || !user) {
      return res.status(404).json({ message: "User not found!" });
    }

    if (user.coins <= 0) {
      return res.status(400).json({ message: "Koin tidak cukup!" });
    }

    const { error: updateError } = await supabase
      .from("users")
      .update({ coins: user.coins - 1 })
      .eq("id", req.user.id);

    if (updateError) throw updateError;

    res.json({ message: "Koin berhasil digunakan", coins: user.coins - 1 });
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
    const { data: user, error } = await supabase
      .from("users")
      .select("coins")
      .eq("id", req.user.id)
      .single();

    if (error || !user) {
      return res.status(404).json({ message: "User not found!" });
    }

    const newCoins = user.coins + amount;

    const { error: updateError } = await supabase
      .from("users")
      .update({ coins: newCoins })
      .eq("id", req.user.id);

    if (updateError) throw updateError;

    res.json({ message: "Koin berhasil ditambahkan", coins: newCoins });
  } catch (err) {
    res.status(500).json({ message: "Terjadi kesalahan!", error: err.message });
  }
});

// MIDDLEWARE - Check if user is an admin
const isAdmin = async (req, res, next) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("role")
      .eq("id", req.user.id)
      .single();

    if (error || !user || user.role !== "admin") {
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
    const { data: users, error } = await supabase
      .from("users")
      .select("id, username, email, coins, created_at");

    if (error) throw error;
    res.json(users);
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
    const { data: targetUser, error: findError } = await supabase
      .from("users")
      .select("coins")
      .eq("id", userId)
      .single();

    if (findError || !targetUser) {
      return res.status(404).json({ message: "Pengguna tidak ditemukan!" });
    }

    const newCoins = targetUser.coins + amount;

    const { error: updateError } = await supabase
      .from("users")
      .update({ coins: newCoins })
      .eq("id", userId);

    if (updateError) throw updateError;

    const { error: logError } = await supabase.from("coin_transactions").insert({
      user_id: userId,
      admin_id: req.user.id,
      amount,
      transaction_type: "admin_add",
      description: `Koin ditambahkan oleh admin ${req.user.username}`,
    });

    if (logError) throw logError;

    res.json({
      message: "Koin berhasil ditambahkan",
      coins: newCoins,
    });
  } catch (err) {
    res.status(500).json({ message: "Terjadi kesalahan!", error: err.message });
  }
});

// ROUTE TERLINDUNGI - Dashboard
app.get("/api/dashboard", verifyToken, (req, res) => {
  // FIX: sebelumnya single quote, jadi ${req.user.username} nggak ke-interpolate
  res.json({ message: `Selamat datang, ${req.user.username}!` });
});

// Jalankan Server
const PORT = process.env.PORT || 8000;

if (process.env.NODE_ENV == "production") {
  app.listen(PORT, () => {
    console.log(`Server berjalan di http://127.0.0.1:${PORT}`);
    console.log("Available endpoints:");
    console.log("- GET /api/test");
    console.log("- POST /api/send-verification");
    console.log("- POST /api/register");
    console.log("- POST /api/login");
    console.log("- GET /api/dashboard [protected]");
  });
}

module.exports = app;