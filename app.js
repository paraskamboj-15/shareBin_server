const express = require('express');
const mongoose = require('mongoose');
const { nanoid } = require('nanoid');
const cors = require('cors');
const multer = require('multer');
const CryptoJS = require('crypto-js');
const bcrypt = require('bcryptjs'); 
require('dotenv').config();

const app = express();
const PORT = process.env.PORT ?? 3004;
const DB_URL = process.env.DB_URL;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

if (!ENCRYPTION_KEY || !DB_URL) {
  console.error("Missing required environment variables.");
  process.exit(1);
}


const FRONTEND_URL = "https://sharebinn.netlify.app";

app.use(
  cors({
    origin: FRONTEND_URL,
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "x-share-password"],
  })
);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && origin !== FRONTEND_URL) {
    return res.status(403).json({ error: "Forbidden: Invalid origin" });
  }
  next();
});

// Middleware
app.use(express.json());

// MongoDB connection
mongoose.connect(DB_URL)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });

// Mongoose schema
const shareSchema = new mongoose.Schema({
  shareId: { type: String, required: true, unique: true },
  content: String,
  contentType: { type: String, default: 'text/plain' },
  fileData: { type: String, default: null },  
  fileName: { type: String, default: null },
  fileUrl: String,
  isEncrypted: { type: Boolean, default: false },
  passwordHash: { type: String, default: null },
  createdAt: { type: Date, default: Date.now },
});

const Share = mongoose.model('Share', shareSchema);
function computeExpiresAt() {
  return null;
}


const storage = multer.memoryStorage();
const upload = multer({ storage });

// POST /api/share
app.post('/api/share', upload.single('file'), async (req, res, next) => {
  try {
    const shareId = nanoid(6);
    const { content, contentType, encrypt, password } = req.body;

    if (!content && !req.file) {
      return res.status(400).json({ error: 'Either content or file is required.' });
    }

    const shouldEncrypt =
      encrypt === true || encrypt === "true" || !!password === true;

    let finalContent = content || null;
    let passwordHash = null;

    if (password) {
      passwordHash = await bcrypt.hash(String(password), 10);
    }

    const expiresAt = computeExpiresAt();

    if (finalContent && shouldEncrypt) {
      finalContent = CryptoJS.AES.encrypt(finalContent, ENCRYPTION_KEY).toString();
    }

    let fileData = null;
    let fileName = null;

    if (req.file) {
      const base64 = req.file.buffer.toString("base64");

      if (shouldEncrypt) {
        fileData = CryptoJS.AES.encrypt(base64, ENCRYPTION_KEY).toString();
      } else {
        fileData = base64;
      }

      fileName = req.file.originalname;
    }

    const share = new Share({
      shareId,
      content: finalContent,
      contentType: contentType || req.file?.mimetype || "text/plain",
      fileData,
      fileName,
      isEncrypted: shouldEncrypt,
      passwordHash,
      expiresAt,
    });

    await share.save();
    res.status(201).json({ shareId, expiresAt });
  } catch (error) {
    next(error);
  }
});


// GET /api/share/:id

app.get("/api/share/:id", async (req, res, next) => {
  try {
    const share = await Share.findOne({ shareId: req.params.id });
    if (!share) return res.status(404).json({ error: "Share not found" });

    if (share.passwordHash) {
      const providedPassword = req.headers["x-share-password"] || req.query.password;

      if (!providedPassword)
        return res.status(401).json({ error: "Password required" });

      const ok = await bcrypt.compare(String(providedPassword), share.passwordHash);
      if (!ok) return res.status(403).json({ error: "Invalid password" });
    }

    const responseShare = share.toObject();
    delete responseShare.passwordHash;

    if (share.isEncrypted) {
      if (share.content) {
        const bytes = CryptoJS.AES.decrypt(share.content, ENCRYPTION_KEY);
        responseShare.content = bytes.toString(CryptoJS.enc.Utf8);
      }

      if (share.fileData) {
        responseShare.hasFile = true;
        responseShare.fileName = share.fileName;
      } else {
        responseShare.hasFile = false;
      }

      return res.json(responseShare);
    }

    // non encrypted
    if (share.fileData) {
      responseShare.fileUrl = `data:${share.contentType};base64,${share.fileData}`;
    }

    return res.json(responseShare);
  } catch (error) {
    next(error);
  }
});


// GET /api/share/:id/file (decrypt encrypted files)

app.get("/api/share/:id/file", async (req, res, next) => {
  try {
    const share = await Share.findOne({ shareId: req.params.id });
    if (!share || !share.fileData)
      return res.status(404).json({ error: "File not found" });

    if (share.passwordHash) {
      const providedPassword = req.headers["x-share-password"] || req.query.password;

      if (!providedPassword)
        return res.status(401).json({ error: "Password required" });

      const ok = await bcrypt.compare(String(providedPassword), share.passwordHash);
      if (!ok) return res.status(403).json({ error: "Invalid password" });
    }

    if (!share.isEncrypted)
      return res.status(400).json({ error: "File is not encrypted" });

    try {
      const bytes = CryptoJS.AES.decrypt(share.fileData, ENCRYPTION_KEY);
      const decryptedBase64 = bytes.toString(CryptoJS.enc.Utf8);
      const fileBuffer = Buffer.from(decryptedBase64, "base64");

      res.set("Content-Type", share.contentType || "application/octet-stream");
      res.set("Content-Disposition", `attachment; filename="${share.fileName || 'file'}"`);

      return res.send(fileBuffer);
    } catch {
      return res.status(500).json({ error: "Failed to decrypt file data" });
    }
  } catch (error) {
    next(error);
  }
});


// Root Route

app.get("/", (req, res) => {
  res.send("Share Bin API is working");
});


// 404 Handler

app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});


// Error Handler

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
