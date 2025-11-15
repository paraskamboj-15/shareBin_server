const express = require('express');
const mongoose = require('mongoose');
const { nanoid } = require('nanoid');
const cors = require('cors');
const multer = require('multer');
// no filesystem usage for uploads — use memory storage to avoid writing to disk
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

// uploads will be kept in memory (no /uploads static route)

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
  // fileData stores base64 (or encrypted base64) when a file is uploaded. We avoid writing files to disk.
  fileData: { type: String, default: null },
  fileName: { type: String, default: null },
  fileUrl: String,
  isEncrypted: { type: Boolean, default: false },
  passwordHash: { type: String, default: null },
  expiresAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
});

// Optional TTL index (CAUTION: this would NOT delete files from disk)
// shareSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const Share = mongoose.model('Share', shareSchema);
// Helpers
// expiry removed — server will not set automatic expiry to reduce storage churn on free hosts
function computeExpiresAt() {
  return null;
}

// No periodic purge — expiry disabled to avoid background storage operations on limited hosts

// File upload setup: use memory storage to avoid writing to disk on the hosting platform
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

    // If password provided, force encryption so that static /uploads URL isn't readable
    const shouldEncrypt =
      encrypt === true || encrypt === "true" || !!password === true;

    let fileUrl = null;
    let finalContent = content || null;

    let passwordHash = null;
    if (password && String(password).length > 0) {
      passwordHash = await bcrypt.hash(String(password), 10);
    }

    const expiresAt = computeExpiresAt();

    if (finalContent && shouldEncrypt) {
      finalContent = CryptoJS.AES.encrypt(finalContent, ENCRYPTION_KEY).toString();
    }

    if (req.file) {
      // store file in memory as base64 (encrypted if requested) — no disk I/O
      const base64 = req.file.buffer.toString('base64');
      if (shouldEncrypt) {
        const encrypted = CryptoJS.AES.encrypt(base64, ENCRYPTION_KEY).toString();
        // store encrypted base64 blob
        fileUrl = null;
        // will save encrypted data into fileData field below
        req._incomingFileBase64 = encrypted;
      } else {
        req._incomingFileBase64 = base64;
      }
      // preserve metadata
      req._incomingFileName = req.file.originalname;
      req._incomingFileType = req.file.mimetype;
    }

    const shareObj = {
      shareId,
      content: finalContent,
      contentType: contentType || req.file?.mimetype || 'text/plain',
      fileUrl: fileUrl || null,
      isEncrypted: shouldEncrypt,
      passwordHash,
      expiresAt,
    };

    if (req._incomingFileBase64) {
      shareObj.fileData = req._incomingFileBase64;
      shareObj.fileName = req._incomingFileName || null;
      // For non-encrypted files we also optionally expose a data URL client-side via response
    }

    const share = new Share(shareObj);

    await share.save();
    res.status(201).json({ shareId, expiresAt });
  } catch (error) {
    next(error);
  }
});

// GET /api/share/:id
app.get('/api/share/:id', async (req, res, next) => {
  try {
    const share = await Share.findOne({ shareId: req.params.id });
    if (!share) {
      return res.status(404).json({ error: 'Share not found' });
    }

    // Expiry disabled — server does not auto-delete to avoid storage churn on limited hosts

    // If password protected, verify
    if (share.passwordHash) {
      const providedPassword =
        req.headers["x-share-password"] || req.query.password;
      if (!providedPassword) {
        return res.status(401).json({ error: "Password required" });
      }
      const ok = await bcrypt.compare(String(providedPassword), share.passwordHash);
      if (!ok) {
        return res.status(403).json({ error: "Invalid password" });
      }
    }

    const responseShare = share.toObject();
    delete responseShare.passwordHash;

    // If encrypted and has both text and file, return text + hasFile flag
    if (share.isEncrypted) {
      if (share.content) {
        const bytes = CryptoJS.AES.decrypt(share.content, ENCRYPTION_KEY);
        const originalContent = bytes.toString(CryptoJS.enc.Utf8);
        responseShare.content = originalContent;
      }
      if (share.fileData) {
        responseShare.hasFile = true;
        responseShare.fileName = share.fileName || null;
        responseShare.contentType = share.contentType || 'application/octet-stream';
      } else {
        responseShare.hasFile = false;
      }
      return res.json(responseShare);
    }

    // Non-encrypted: handle file or text
    if (share.fileData) {
      responseShare.fileUrl = `data:${share.contentType};base64,${share.fileData}`;
      responseShare.fileName = share.fileName || null;
      return res.json(responseShare);
    }
    // No file data — return JSON (text-only share)
    return res.json(responseShare);
// GET /api/share/:id/file - fetch decrypted file blob (for encrypted shares)
app.get('/api/share/:id/file', async (req, res, next) => {
  try {
    const share = await Share.findOne({ shareId: req.params.id });
    if (!share || !share.fileData) {
      return res.status(404).json({ error: 'File not found' });
    }
    // If password protected, verify
    if (share.passwordHash) {
      const providedPassword =
        req.headers["x-share-password"] || req.query.password;
      if (!providedPassword) {
        return res.status(401).json({ error: "Password required" });
      }
      const ok = await bcrypt.compare(String(providedPassword), share.passwordHash);
      if (!ok) {
        return res.status(403).json({ error: "Invalid password" });
      }
    }
    if (!share.isEncrypted) {
      // Should not be used for non-encrypted files
      return res.status(400).json({ error: 'File is not encrypted' });
    }
    // Decrypt and send file
    try {
      const bytes = CryptoJS.AES.decrypt(share.fileData, ENCRYPTION_KEY);
      const decryptedBase64 = bytes.toString(CryptoJS.enc.Utf8);
      const fileBuffer = Buffer.from(decryptedBase64, "base64");
      res.set("Content-Type", share.contentType || "application/octet-stream");
      res.set("Content-Disposition", `attachment; filename=\"${share.fileName || 'file'}\"`);
      return res.send(fileBuffer);
    } catch (e) {
      return res.status(500).json({ error: "Failed to decrypt file data" });
    }
  } catch (error) {
    next(error);
  }
});
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
