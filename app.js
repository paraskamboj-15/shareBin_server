const express = require('express');
const mongoose = require('mongoose');
const { nanoid } = require('nanoid');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3003;
const DB_URL = process.env.DB_URL;

// Middleware
app.use(cors());
app.use(express.json());

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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
  createdAt: { type: Date, default: Date.now },
});
const Paste = mongoose.model('Paste', pasteSchema);

// File upload setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => cb(null, `${nanoid(6)}-${Date.now()}-${file.originalname}`),
});
const upload = multer({ storage });

// POST /api/paste
app.post('/api/paste', upload.single('file'), async (req, res, next) => {
  try {
    const pasteId = nanoid(6);
    const { content, contentType } = req.body;
    let fileUrl = null;

    if (!content && !req.file) {
      return res.status(400).json({ error: 'Either content or file is required.' });
    }

    if (req.file) {
      fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    }

    const paste = new Paste({
      pasteId,
      content: content || null,
      contentType: contentType || req.file?.mimetype || 'text/plain',
      fileUrl,
    });

    await paste.save();
    res.status(201).json({ pasteId });
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
    res.json(paste);
  } catch (error) {
    next(error);
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.send('PasteBin API is working');
});

// 404 handler for unknown routes
app.use((req, res, next) => {
  res.status(404).json({ error: 'Route not found' });
});

// Central error-handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
