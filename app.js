const express = require('express');
const mongoose = require('mongoose');
const { nanoid } = require('nanoid');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const CryptoJS = require('crypto-js');
const bcrypt = require('bcryptjs'); 
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT ?? 3004;
const DB_URL = process.env.DB_URL;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

if (!ENCRYPTION_KEY || !DB_URL) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

// Middleware
app.use(cors());
app.use(express.json());

const UPLOADS_DIR = path.join(__dirname, "uploads");
app.use("/uploads", express.static(UPLOADS_DIR));

// MongoDB connection
mongoose.connect(DB_URL)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });

// Mongoose schema
const pasteSchema = new mongoose.Schema({
  pasteId: { type: String, required: true, unique: true },
  content: String,
  contentType: { type: String, default: 'text/plain' },
  fileUrl: String,
  isEncrypted: { type: Boolean, default: false },
  passwordHash: { type: String, default: null }, // NEW
  expiresAt: { type: Date, default: null },      // NEW
  createdAt: { type: Date, default: Date.now },
});

// Optional TTL index (CAUTION: this would NOT delete files from disk)
// pasteSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const Paste = mongoose.model('Paste', pasteSchema);
// Helpers
const EXPIRY_MAP_MS = {
  "12h": 12 * 60 * 60 * 1000,
  "12hr": 12 * 60 * 60 * 1000,
  "12hrs": 12 * 60 * 60 * 1000,
  "1d": 24 * 60 * 60 * 1000,
  "1day": 24 * 60 * 60 * 1000,
  "2d": 2 * 24 * 60 * 60 * 1000,
  "2days": 2 * 24 * 60 * 60 * 1000,
  "4d": 4 * 24 * 60 * 60 * 1000,
  "4days": 4 * 24 * 60 * 60 * 1000,
  "5d": 5 * 24 * 60 * 60 * 1000,
  "5days": 5 * 24 * 60 * 60 * 1000,
  "none": null,
  "no_deletion": null,
  "never": null,
};

function computeExpiresAt(expiresIn) {
  if (!expiresIn) return null;
  const v = String(expiresIn).trim().toLowerCase();
  if (v in EXPIRY_MAP_MS) {
    const ms = EXPIRY_MAP_MS[v];
    return ms ? new Date(Date.now() + ms) : null;
  }
  // generic patterns like "3h" or "7days"
  const m = v.match(/^(\d+)\s*(h|hr|hrs|hour|hours|d|day|days)$/);
  if (m) {
    const n = parseInt(m[1], 10);
    const unit = m[2];
    const ms =
      unit.startsWith("h") ? n * 60 * 60 * 1000 : n * 24 * 60 * 60 * 1000;
    return new Date(Date.now() + ms);
  }
  return null;
}

function filePathFromUrl(fileUrl) {
  if (!fileUrl) return null;
  const filename = path.basename(fileUrl);
  return path.join(UPLOADS_DIR, filename);
}

async function deletePasteAndFile(paste) {
  try {
    if (paste.fileUrl) {
      const fp = filePathFromUrl(paste.fileUrl);
      if (fp && fs.existsSync(fp)) {
        fs.unlinkSync(fp);
      }
    }
  } catch (e) {
    console.error("Error deleting file:", e.message);
  } finally {
    try {
      await Paste.deleteOne({ _id: paste._id });
    } catch (e) {
      console.error("Error deleting paste doc:", e.message);
    }
  }
}

async function purgeExpiredPastes() {
  const now = new Date();
  const expired = await Paste.find({ expiresAt: { $ne: null, $lte: now } });
  for (const p of expired) {
    await deletePasteAndFile(p);
  }
}

// run cleanup every 15 minutes
setInterval(() => {
  purgeExpiredPastes().catch((e) =>
    console.error("cleanup error:", e.message)
  );
}, 15 * 60 * 1000);

// File upload setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const safeFilename = file.originalname.replace(/\s+/g, "_");
    cb(null, `${nanoid(8)}-${Date.now()}-${safeFilename}`);
  },
});
const upload = multer({ storage });

// POST /api/paste
app.post('/api/paste', upload.single('file'), async (req, res, next) => {
  try {
    const pasteId = nanoid(6);
    const { content, contentType, encrypt, password, expiresIn } = req.body;

    if (!content && !req.file) {
      return res.status(400).json({ error: 'Either content or file is required.' });
    }

    // If password provided, force encryption so that static /uploads URL isn't readable
    const shouldEncrypt =
      encrypt === true || encrypt === "true" || !!password === true;

    let fileUrl = null;
    let finalContent = content || null;

    let passwordHash = null;
    if (password && String(password).length > 0) {
      passwordHash = await bcrypt.hash(String(password), 10);
    }

    const expiresAt = computeExpiresAt(expiresIn);

    if (finalContent && shouldEncrypt) {
      finalContent = CryptoJS.AES.encrypt(finalContent, ENCRYPTION_KEY).toString();
    }

    if (req.file) {
      fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;

      if (shouldEncrypt) {
        const fileBuffer = fs.readFileSync(req.file.path);
        const encryptedFileContent = CryptoJS.AES.encrypt(
          fileBuffer.toString("base64"),
          ENCRYPTION_KEY
        ).toString();
        fs.writeFileSync(req.file.path, encryptedFileContent);
      }
    }

    const paste = new Paste({
      pasteId,
      content: finalContent,
      contentType: contentType || req.file?.mimetype || 'text/plain',
      fileUrl,
      isEncrypted: shouldEncrypt,
      passwordHash,
      expiresAt,
    });

    await paste.save();
    res.status(201).json({ pasteId, expiresAt });
  } catch (error) {
    next(error);
  }
});

// GET /api/paste/:id
app.get('/api/paste/:id', async (req, res, next) => {
  try {
    const paste = await Paste.findOne({ pasteId: req.params.id });
    if (!paste) {
      return res.status(404).json({ error: 'Paste not found' });
    }

    // Expiry check — if expired, clean up and return 410 Gone
    if (paste.expiresAt && paste.expiresAt <= new Date()) {
      await deletePasteAndFile(paste);
      return res.status(410).json({ error: "Paste expired and deleted" });
    }

    // If password protected, verify
    if (paste.passwordHash) {
      const providedPassword =
        req.headers["x-paste-password"] || req.query.password;
      if (!providedPassword) {
        return res.status(401).json({ error: "Password required" });
      }
      const ok = await bcrypt.compare(String(providedPassword), paste.passwordHash);
      if (!ok) {
        return res.status(403).json({ error: "Invalid password" });
      }
    }

    const responsePaste = paste.toObject();
    delete responsePaste.passwordHash;

    // Decrypt content if needed
    if (paste.isEncrypted && paste.content) {
      const bytes = CryptoJS.AES.decrypt(paste.content, ENCRYPTION_KEY);
      const originalContent = bytes.toString(CryptoJS.enc.Utf8);
      responsePaste.content = originalContent;
      return res.json(responsePaste);
    }

    // If encrypted file, decrypt and stream binary
    if (paste.isEncrypted && paste.fileUrl) {
      const filePath = filePathFromUrl(paste.fileUrl);

      if (filePath && fs.existsSync(filePath)) {
        const encryptedContent = fs.readFileSync(filePath, "utf8");
        const bytes = CryptoJS.AES.decrypt(encryptedContent, ENCRYPTION_KEY);
        const decryptedBase64 = bytes.toString(CryptoJS.enc.Utf8);
        const fileBuffer = Buffer.from(decryptedBase64, "base64");

        res.set("Content-Type", paste.contentType);
        return res.send(fileBuffer);
      } else {
        return res.status(404).json({ error: "Encrypted file missing" });
      }
    }

    // Non-encrypted case: just return JSON (for files this includes the fileUrl)
    return res.json(responsePaste);
  } catch (error) {
    next(error);
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.send('Share Bin API is working');
});

// 404 handler for unknown routes
app.use((req, res, next) => {
  res.status(404).json({ error: 'Route not found' });
});

// Central error-handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  console.error('Unhandled error stack:', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
