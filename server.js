const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const cors = require('cors');
const axios = require('axios');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Load environment variables
require('dotenv').config();

// Validate Google Maps API key at startup
const GOOGLE_MAPS_API_KEY = process.env.GOOGLE_MAPS_API_KEY;
if (!GOOGLE_MAPS_API_KEY) {
  console.error('Google Maps API key is missing. Please set GOOGLE_MAPS_API_KEY in the .env file.');
  process.exit(1);
}

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

const app = express();

// Configure CORS to allow requests from your frontend
app.use(cors({
  origin: 'http://localhost:3002',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type'],
}));

// Serve the uploads directory statically
app.use('/uploads', express.static('uploads'));

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

// Apply express.json() after multer middleware to avoid interfering with multipart/form-data
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// In-memory store for OTPs (for simplicity; use a database or Redis in production)
const otpStore = new Map();

// MySQL Database Connection Pool
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'runa',
  database: 'volay',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  multipleStatements: true,
});

// Initialize Database and Tables
const initializeDatabase = async () => {
  try {
    const connection = await mysql.createConnection({
      host: 'localhost',
      user: 'root',
      password: 'runa',
      multipleStatements: true,
    });

    console.log('Temporary connection established');
    await connection.query('CREATE DATABASE IF NOT EXISTS volay');
    console.log("Database 'volay' created or already exists");
    await connection.query('USE volay');
    console.log("Using database 'volay'");

    // Caregivers table (create first due to foreign key dependency)
    await connection.query(`
      CREATE TABLE IF NOT EXISTS caregivers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        phone_number VARCHAR(255),
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL,
        relationship VARCHAR(255),
        age INT,
        birthdate DATE,
        gender VARCHAR(50),
        num_patients INT DEFAULT 0,
        experience_level VARCHAR(255),
        backup_contact_name VARCHAR(255),
        backup_contact_phone VARCHAR(255),
        notifications_email BOOLEAN,
        notifications_sms BOOLEAN,
        notifications_app BOOLEAN,
        profile_picture VARCHAR(255),
        address VARCHAR(255),
        terms_accepted BOOLEAN,
        privacy_accepted BOOLEAN,
        newsletter_subscribed BOOLEAN
      )
    `);

    // Fix NULL emails in caregivers table
    const [caregivers] = await connection.query('SELECT * FROM caregivers WHERE email IS NULL');
    if (caregivers.length > 0) {
      await connection.query('UPDATE caregivers SET email = CONCAT("caregiver", id, "@example.com") WHERE email IS NULL');
      console.log('Updated NULL emails in caregivers table with placeholder emails');
    }

    // Patients table (removed medical_history TEXT field)
    await connection.query(`
      CREATE TABLE IF NOT EXISTS patients (
        id INT AUTO_INCREMENT PRIMARY KEY,
        caregiver_id INT,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        phone_number VARCHAR(20),
        password VARCHAR(255),
        role VARCHAR(50) NOT NULL,
        date_of_birth DATE,
        gender VARCHAR(20),
        dementia_stage VARCHAR(20),
        known_conditions TEXT,
        cognitive_abilities TEXT,
        profile_picture VARCHAR(255),
        emergency_contact VARCHAR(255),
        interests TEXT,
        past_occupation VARCHAR(255),
        memory_book_entries TEXT,
        voice_sample VARCHAR(255),
        favorite_people TEXT,
        living_situation VARCHAR(50),
        mobility_level VARCHAR(50),
        address VARCHAR(255),
        terms_accepted TINYINT(1),
        privacy_accepted TINYINT(1),
        newsletter_subscribed TINYINT(1),
        mood VARCHAR(50),
        cognitive_score INT,
        last_activity TEXT,
        FOREIGN KEY (caregiver_id) REFERENCES caregivers(id)
      )
    `);

    // Migration: Ensure email column is NOT NULL
    const [patients] = await connection.query('SELECT * FROM patients WHERE email IS NULL');
    if (patients.length > 0) {
      await connection.query('UPDATE patients SET email = CONCAT("patient", id, "@example.com") WHERE email IS NULL');
      console.log('Updated NULL emails in patients table with placeholder emails');
    }

    // Medical History table (new table to store medical history entries)
    await connection.query(`
      CREATE TABLE IF NOT EXISTS medical_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        patient_id INT,
        history TEXT NOT NULL,
        recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
      )
    `);

    // Schedules table (updated to include medication_note and completed)
    await connection.query(`
      CREATE TABLE IF NOT EXISTS schedules (
        id INT AUTO_INCREMENT PRIMARY KEY,
        patient_id INT,
        time VARCHAR(255) NOT NULL,
        task VARCHAR(255) NOT NULL,
        medication_note TEXT,
        completed BOOLEAN DEFAULT FALSE,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
      )
    `);

    // Activities table (new)
    await connection.query(`
      CREATE TABLE IF NOT EXISTS activities (
        id INT AUTO_INCREMENT PRIMARY KEY,
        patient_id INT,
        activity TEXT NOT NULL,
        timestamp DATETIME NOT NULL,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
      )
    `);

    // Flashbacks table (new)
    await connection.query(`
      CREATE TABLE IF NOT EXISTS flashbacks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        patient_id INT,
        src VARCHAR(255) NOT NULL,
        alt VARCHAR(255) NOT NULL,
        caption VARCHAR(255) NOT NULL,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
      )
    `);

    // Messages table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        patient_id INT,
        sender VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        type ENUM('text', 'voice') DEFAULT 'text',
        timestamp DATETIME NOT NULL,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
      )
    `);

    // Emergency Contacts table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS emergency_contacts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        patient_id INT,
        name VARCHAR(255) NOT NULL,
        phone VARCHAR(255) NOT NULL,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
      )
    `);

    // Safety Alerts table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS safety_alerts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        patient_id INT,
        message TEXT NOT NULL,
        timestamp DATETIME NOT NULL,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
      )
    `);

    // Mood Entries table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS mood_entries (
        id INT AUTO_INCREMENT PRIMARY KEY,
        patient_id INT,
        date VARCHAR(50) NOT NULL,
        time VARCHAR(50) NOT NULL,
        score INT NOT NULL,
        tags TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
      )
    `);

    // Medications table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS medications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        patient_id INT,
        dose VARCHAR(255) NOT NULL,
        time VARCHAR(50) NOT NULL,
        status ENUM('Taken', 'Missed', 'Pending') DEFAULT 'Pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
      )
    `);

    await connection.end();
    console.log('Database and tables initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err.message);
    throw err;
  }
};

// Middleware to catch unhandled errors
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.message, err.stack);
  res.status(500).json({ message: "Internal server error", error: err.message });
});

// Proxy Endpoints for Google Maps API
// Reverse Geocoding (coordinates to address)
app.get('/api/geocode', async (req, res) => {
  const { lat, lng } = req.query;
  const apiKey = process.env.GOOGLE_MAPS_API_KEY;

  if (!lat || !lng) {
    console.error('Missing lat/lng parameters:', { lat, lng });
    return res.status(400).json({ error: 'Missing latitude or longitude' });
  }

  const url = `https://maps.googleapis.com/maps/api/geocode/json?latlng=${lat},${lng}&key=${apiKey}`;
  console.log('Geocoding URL:', url);

  try {
    const response = await axios.get(url);
    console.log('Geocoding response status:', response.data.status);
    if (response.data.status !== 'OK') {
      console.error('Google Maps API error:', response.data.status, response.data.error_message);
      return res.status(500).json({
        error: `Google Maps API error: ${response.data.status} - ${response.data.error_message || 'Unknown error'}`,
      });
    }
    res.json(response.data);
  } catch (error) {
    console.error('Failed to reverse geocode:', error.message, error.stack);
    res.status(500).json({ error: `Failed to reverse geocode: ${error.message}` });
  }
});

// Geocoding (address to coordinates)
app.get('/api/geocode-address', async (req, res) => {
  const { address } = req.query;
  const apiKey = process.env.GOOGLE_MAPS_API_KEY;

  if (!address) {
    console.error('Missing address parameter:', { address });
    return res.status(400).json({ error: 'Missing address' });
  }

  const url = `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(address)}&key=${apiKey}`;
  console.log('Forward geocoding URL:', url);

  try {
    const response = await axios.get(url);
    console.log('Forward geocoding response status:', response.data.status);
    if (response.data.status !== 'OK') {
      console.error('Google Maps API error:', response.data.status, response.data.error_message);
      return res.status(500).json({
        error: `Google Maps API error: ${response.data.status} - ${response.data.error_message || 'Unknown error'}`,
      });
    }
    res.json(response.data);
  } catch (error) {
    console.error('Failed to geocode address:', error.message, error.stack);
    res.status(500).json({ error: `Failed to geocode address: ${error.message}` });
  }
});

// Directions (fetch route between two addresses)
app.get('/api/directions', async (req, res) => {
  const { origin, destination } = req.query;
  const apiKey = process.env.GOOGLE_MAPS_API_KEY;

  if (!origin || !destination) {
    console.error('Missing origin or destination parameters:', { origin, destination });
    return res.status(400).json({ error: 'Missing origin or destination' });
  }

  const url = `https://maps.googleapis.com/maps/api/directions/json?origin=${encodeURIComponent(origin)}&destination=${encodeURIComponent(destination)}&key=${apiKey}`;
  console.log('Directions URL:', url);

  try {
    const response = await axios.get(url);
    console.log('Directions response status:', response.data.status);
    if (response.data.status !== 'OK') {
      console.error('Google Maps API error:', response.data.status, response.data.error_message);
      return res.status(500).json({
        error: `Google Maps API error: ${response.data.status} - ${response.data.error_message || 'Unknown error'}`,
      });
    }
    res.json(response.data);
  } catch (error) {
    console.error('Failed to fetch directions:', error.message, error.stack);
    res.status(500).json({ error: `Failed to fetch directions: ${error.message}` });
  }
});

// Nearby Places - Police
app.get('/api/nearby/police', async (req, res) => {
  const { lat, lng } = req.query;
  const apiKey = process.env.GOOGLE_MAPS_API_KEY;

  if (!lat || !lng) {
    console.error('Missing lat/lng parameters for nearby police:', { lat, lng });
    return res.status(400).json({ error: 'Missing latitude or longitude' });
  }

  const url = `https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=${lat},${lng}&radius=5000&type=police&key=${apiKey}`;
  console.log('Nearby police URL:', url);

  try {
    const response = await axios.get(url);
    console.log('Nearby police response status:', response.data.status);
    if (response.data.status !== 'OK') {
      console.error('Google Maps API error:', response.data.status, response.data.error_message);
      return res.status(500).json({
        error: `Google Maps API error: ${response.data.status} - ${response.data.error_message || 'Unknown error'}`,
      });
    }
    res.json(response.data);
  } catch (error) {
    console.error('Failed to fetch nearby police stations:', error.message, error.stack);
    res.status(500).json({ error: `Failed to fetch nearby police stations: ${error.message}` });
  }
});

// Nearby Places - Hospital
app.get('/api/nearby/hospital', async (req, res) => {
  const { lat, lng } = req.query;
  const apiKey = process.env.GOOGLE_MAPS_API_KEY;

  if (!lat || !lng) {
    console.error('Missing lat/lng parameters for nearby hospital:', { lat, lng });
    return res.status(400).json({ error: 'Missing latitude or longitude' });
  }

  const url = `https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=${lat},${lng}&radius=5000&type=hospital&key=${apiKey}`;
  console.log('Nearby hospital URL:', url);

  try {
    const response = await axios.get(url);
    console.log('Nearby hospital response status:', response.data.status);
    if (response.data.status !== 'OK') {
      console.error('Google Maps API error:', response.data.status, response.data.error_message);
      return res.status(500).json({
        error: `Google Maps API error: ${response.data.status} - ${response.data.error_message || 'Unknown error'}`,
      });
    }
    res.json(response.data);
  } catch (error) {
    console.error('Failed to fetch nearby hospitals:', error.message, error.stack);
    res.status(500).json({ error: `Failed to fetch nearby hospitals: ${error.message}` });
  }
});

// Optional: Proxy endpoint for Botpress requests (if needed for CORS issues)
app.get('/api/botpress/proxy', async (req, res) => {
  const { url } = req.query;

  if (!url) {
    console.error('Missing URL parameter for Botpress proxy:', { url });
    return res.status(400).json({ error: 'Missing URL parameter' });
  }

  try {
    const response = await axios.get(url);
    res.json(response.data);
  } catch (error) {
    console.error('Failed to proxy Botpress request:', error.message, error.stack);
    res.status(500).json({ error: `Failed to proxy Botpress request: ${error.message}` });
  }
});

// Signup endpoint
app.post('/signup/email', async (req, res) => {
  const { name, email, phoneNumber, password, role, termsAccepted, privacyAccepted, newsletterSubscribed } = req.body;
  console.log("Signup request body:", req.body);

  if (!role || (role !== 'caregiver' && role !== 'patient')) {
    console.error("Invalid role:", role);
    return res.status(400).json({ message: "Invalid role. Must be 'caregiver' or 'patient'" });
  }

  if (!name || !email || !phoneNumber || !password) {
    console.error("Missing required fields:", { name, email, phoneNumber, password });
    return res.status(400).json({ message: "Missing required fields" });
  }

  try {
    const db = await pool.getConnection();

    const [existingUsers] = await db.query(`SELECT * FROM ${role}s WHERE email = ?`, [email]);
    if (existingUsers.length > 0) {
      db.release();
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const query = `INSERT INTO ${role}s (name, email, phone_number, password, role, terms_accepted, privacy_accepted, newsletter_subscribed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    const [result] = await db.query(query, [
      name,
      email,
      phoneNumber,
      hashedPassword,
      role,
      termsAccepted ? 1 : 0,
      privacyAccepted ? 1 : 0,
      newsletterSubscribed ? 1 : 0,
    ]);

    console.log("Signup successful, userId:", result.insertId);
    // Log the current state of the table to verify insertion
    const [newUser] = await db.query(`SELECT * FROM ${role}s WHERE id = ?`, [result.insertId]);
    console.log(`Inserted ${role}:`, newUser[0]);

    res.json({ userId: result.insertId });
    db.release();
  } catch (err) {
    console.error("Signup error:", err.message);
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(400).json({ message: "Email already exists" });
    }
    res.status(500).json({ message: "Server error during signup", error: err.message });
  }
});

// Signin endpoint
app.post('/signin', async (req, res) => {
  const { identifier, password, role } = req.body;
  console.log("Signin request:", { identifier, password, role });

  if (!role || (role !== 'caregiver' && role !== 'patient')) {
    console.error("Invalid role during signin:", role);
    return res.status(400).json({ message: "Invalid role" });
  }

  if (!identifier) {
    console.error("Identifier is missing");
    return res.status(400).json({ message: "Phone number or email is required" });
  }

  const trimmedIdentifier = identifier.trim();
  console.log("Trimmed identifier:", trimmedIdentifier);

  try {
    const db = await pool.getConnection();
    let query;
    let params;
    if (role === 'patient') {
      query = `SELECT * FROM patients WHERE (email = ? OR phone_number = ?) AND role = ?`;
      params = [trimmedIdentifier, trimmedIdentifier, role];
    } else {
      query = `SELECT * FROM caregivers WHERE (email = ? OR phone_number = ?) AND role = ?`;
      params = [trimmedIdentifier, trimmedIdentifier, role];
    }
    console.log("Executing query:", query, "with params:", params);
    const [results] = await db.query(query, params);

    if (results.length === 0) {
      console.log("No user found for identifier:", trimmedIdentifier, "and role:", role);
      db.release();
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = results[0];
    console.log("User found:", user);

    if (role === 'patient') {
      if (!user.password) {
        console.log("Patient has no password set, allowing sign-in without password");
        res.json({ userId: user.id, name: user.name, role: user.role });
        db.release();
        return;
      }
    }

    if (!password) {
      console.log("Password required but not provided for user:", user.id);
      db.release();
      return res.status(401).json({ message: "Password is required" });
    }

    const match = await bcrypt.compare(password, user.password);
    console.log("Password match:", match);
    if (!match) {
      console.log("Password does not match for user:", user.id);
      db.release();
      return res.status(401).json({ message: "Invalid credentials" });
    }

    console.log("Signin successful for user:", user.id);
    res.json({ userId: user.id, name: user.name, role: user.role });
    db.release();
  } catch (err) {
    console.error("Signin error:", err.message);
    res.status(500).json({ message: "Sign-in failed", error: err.message });
  }
});

// Generate OTP endpoint
app.post('/generate-otp', async (req, res) => {
  const { identifier, role } = req.body;
  console.log(`Generate OTP request for ${role} with identifier: ${identifier}`);

  if (!role || (role !== 'caregiver' && role !== 'patient')) {
    console.error("Invalid role:", role);
    return res.status(400).json({ message: "Invalid role" });
  }

  if (!identifier) {
    console.error("Identifier is missing");
    return res.status(400).json({ message: "Phone number or email is required" });
  }

  const trimmedIdentifier = identifier.trim();
  console.log("Trimmed identifier:", trimmedIdentifier);

  try {
    const db = await pool.getConnection();
    let query;
    let params;
    if (role === 'patient') {
      query = `SELECT * FROM patients WHERE (email = ? OR phone_number = ?) AND role = ?`;
      params = [trimmedIdentifier, trimmedIdentifier, role];
    } else {
      query = `SELECT * FROM caregivers WHERE (email = ? OR phone_number = ?) AND role = ?`;
      params = [trimmedIdentifier, trimmedIdentifier, role];
    }
    console.log("Executing query:", query, "with params:", params);
    const [results] = await db.query(query, params);

    if (results.length === 0) {
      console.log("No user found for identifier:", trimmedIdentifier, "and role:", role);
      db.release();
      return res.status(404).json({ message: "User not found" });
    }

    const user = results[0];
    console.log("User found:", { id: user.id, email: user.email, phone_number: user.phone_number, role: user.role });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    console.log(`Generated OTP for user ${user.id}: ${otp}`);
    otpStore.set(trimmedIdentifier, { otp, role, expires: Date.now() + 10 * 60 * 1000 });
    res.status(200).json({ message: 'OTP generated successfully', otp });
    db.release();
  } catch (err) {
    console.error('Error generating OTP:', err.message);
    res.status(500).json({ message: 'Failed to generate OTP', error: err.message });
  }
});

// Reset Password endpoint
app.post('/reset-password', async (req, res) => {
  const { identifier, otp, newPassword, role } = req.body;
  console.log(`Reset password request for ${role} with identifier: ${identifier}`);

  if (!role || (role !== 'caregiver' && role !== 'patient')) {
    console.error("Invalid role:", role);
    return res.status(400).json({ message: "Invalid role" });
  }

  if (!identifier) {
    console.error("Identifier is missing");
    return res.status(400).json({ message: "Phone number or email is required" });
  }

  if (!otp || !newPassword) {
    console.error("OTP or new password is missing");
    return res.status(400).json({ message: "OTP and new password are required" });
  }

  const trimmedIdentifier = identifier.trim();
  console.log("Trimmed identifier:", trimmedIdentifier);

  const storedOtpData = otpStore.get(trimmedIdentifier);
  if (!storedOtpData) {
    return res.status(400).json({ message: 'OTP not found or expired' });
  }
  if (storedOtpData.role !== role) {
    return res.status(400).json({ message: 'Invalid role for this OTP' });
  }
  if (storedOtpData.expires < Date.now()) {
    otpStore.delete(trimmedIdentifier);
    return res.status(400).json({ message: 'OTP has expired' });
  }
  if (storedOtpData.otp !== otp) {
    return res.status(400).json({ message: 'Invalid OTP' });
  }

  try {
    const db = await pool.getConnection();
    let query;
    let params;
    if (role === 'patient') {
      query = `SELECT * FROM patients WHERE (email = ? OR phone_number = ?) AND role = ?`;
      params = [trimmedIdentifier, trimmedIdentifier, role];
    } else {
      query = `SELECT * FROM caregivers WHERE (email = ? OR phone_number = ?) AND role = ?`;
      params = [trimmedIdentifier, trimmedIdentifier, role];
    }
    const [users] = await db.query(query, params);

    if (users.length === 0) {
      db.release();
      return res.status(404).json({ message: 'User not found' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    if (role === 'patient') {
      await db.query(
        'UPDATE patients SET password = ? WHERE (email = ? OR phone_number = ?) AND role = ?',
        [hashedPassword, trimmedIdentifier, trimmedIdentifier, role]
      );
    } else {
      await db.query(
        'UPDATE caregivers SET password = ? WHERE (email = ? OR phone_number = ?) AND role = ?',
        [hashedPassword, trimmedIdentifier, trimmedIdentifier, role]
      );
    }

    otpStore.delete(trimmedIdentifier);
    res.status(200).json({ message: 'Password reset successfully' });
    db.release();
  } catch (err) {
    console.error('Error resetting password:', err.message);
    res.status(500).json({ message: 'Failed to reset password', error: err.message });
  }
});

// Add patient under a caregiver endpoint
app.post('/caregivers/:caregiverId/patients', async (req, res) => {
  const { caregiverId } = req.params;
  const { name, dob, contactInfo, dementiaStage, emergencyContact } = req.body;
  console.log("Add patient request body:", req.body, "for caregiverId:", caregiverId);

  if (!name || !dob || !contactInfo) {
    console.error("Missing required fields:", { name, dob, contactInfo });
    return res.status(400).json({ message: "Missing required fields: name, date of birth, and phone number are required" });
  }

  try {
    const db = await pool.getConnection();

    const [caregiver] = await db.query('SELECT * FROM caregivers WHERE id = ?', [caregiverId]);
    if (caregiver.length === 0) {
      db.release();
      return res.status(404).json({ message: "Caregiver not found" });
    }

    const placeholderEmail = `patient_${Date.now()}@example.com`;

    const query = `
      INSERT INTO patients (
        caregiver_id, name, email, phone_number, role, date_of_birth, 
        dementia_stage, emergency_contact
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const [result] = await db.query(query, [
      caregiverId,
      name,
      placeholderEmail,
      contactInfo,
      'patient',
      dob,
      dementiaStage || '',
      emergencyContact || '',
    ]);

    console.log("Patient added successfully, patientId:", result.insertId);
    // Log the inserted patient
    const [newPatient] = await db.query('SELECT * FROM patients WHERE id = ?', [result.insertId]);
    console.log("Inserted patient:", newPatient[0]);

    await db.query('UPDATE caregivers SET num_patients = num_patients + 1 WHERE id = ?', [caregiverId]);

    res.status(201).json({ patientId: result.insertId });
    db.release();
  } catch (err) {
    console.error("Error adding patient:", err.message);
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(400).json({ message: "A patient with this phone number already exists" });
    } else if (err.code === "ER_NO_REFERENCED_ROW_2") {
      return res.status(400).json({ message: "Invalid caregiver ID: Caregiver does not exist" });
    }
    res.status(500).json({ message: "Server error while adding patient", error: err.message });
  }
});

// Fetch caregiver details
app.get('/caregivers/:id', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM caregivers WHERE id = ?', [req.params.id]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Caregiver not found' });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error('Error fetching caregiver:', err.message);
    res.status(500).json({ message: 'Failed to fetch caregiver', error: err.message });
  }
});

// Update caregiver profile
app.put('/caregivers/:id', upload.single('profile_picture'), async (req, res) => {
  const { id } = req.params;
  const {
    name,
    address,
    relationship,
    age,
    birthdate,
    gender,
    num_patients,
    experience_level,
    backup_contact_name,
    backup_contact_phone,
    notifications_email,
    notifications_sms,
    notifications_app,
  } = req.body;
  const avatar_url = req.file ? `/uploads/${req.file.filename}` : undefined;

  // Log incoming request data for debugging
  console.log("PUT /caregivers/:id received:");
  console.log("req.body:", req.body);
  console.log("req.file:", req.file);
  console.log("Parsed fields:", { name, avatar_url, address });

  try {
    const updates = {};
    if (name) updates.name = name;
    if (avatar_url) updates.avatar_url = avatar_url;
    if (address) updates.address = address;
    if (relationship) updates.relationship = relationship;
    if (age) updates.age = parseInt(age);
    if (birthdate) updates.birthdate = birthdate;
    if (gender) updates.gender = gender;
    if (num_patients) updates.num_patients = parseInt(num_patients);
    if (experience_level) updates.experience_level = experience_level;
    if (backup_contact_name) updates.backup_contact_name = backup_contact_name;
    if (backup_contact_phone) updates.backup_contact_phone = backup_contact_phone;
    if (notifications_email) updates.notifications_email = notifications_email === '1';
    if (notifications_sms) updates.notifications_sms = notifications_sms === '1';
    if (notifications_app) updates.notifications_app = notifications_app === '1';

    // If no fields are provided to update, return the current caregiver data
    if (Object.keys(updates).length === 0) {
      const [caregiver] = await pool.query('SELECT * FROM caregivers WHERE id = ?', [id]);
      if (caregiver.length === 0) {
        return res.status(404).json({ message: 'Caregiver not found' });
      }
      return res.json({ ...caregiver[0], profilePictureUrl: avatar_url });
    }

    const fields = Object.keys(updates).map(field => `${field} = ?`).join(', ');
    const values = Object.values(updates);

    const [result] = await pool.query(
      `UPDATE caregivers SET ${fields} WHERE id = ?`,
      [...values, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Caregiver not found' });
    }

    const [updatedCaregiver] = await pool.query('SELECT * FROM caregivers WHERE id = ?', [id]);
    res.json({ ...updatedCaregiver[0], profilePictureUrl: avatar_url });
  } catch (err) {
    console.error('Error updating caregiver profile:', err.message);
    res.status(500).json({ message: 'Failed to update caregiver profile', error: err.message });
  }
});

// Fetch patients for a caregiver
app.get('/caregivers/:id/patients', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM patients WHERE caregiver_id = ?', [req.params.id]);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching patients for caregiver:', err.message);
    res.status(500).json({ message: 'Failed to fetch patients', error: err.message });
  }
});

// Fetch patient details
app.get('/patients/:id', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM patients WHERE id = ?', [req.params.id]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Patient not found' });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error('Error fetching patient:', err.message);
    res.status(500).json({ message: 'Failed to fetch patient', error: err.message });
  }
});

// Update patient profile
app.put('/patients/:id', async (req, res) => {
  const { id } = req.params;
  const { name, profile_picture, address } = req.body;

  if (!name && !profile_picture && !address) {
    return res.status(400).json({ message: 'At least one field (name, profile_picture, address) is required' });
  }

  try {
    const updates = {};
    if (name) updates.name = name;
    if (profile_picture) updates.profile_picture = profile_picture;
    if (address) updates.address = address;

    const fields = Object.keys(updates).map(field => `${field} = ?`).join(', ');
    const values = Object.values(updates);

    const [result] = await pool.query(
      `UPDATE patients SET ${fields} WHERE id = ?`,
      [...values, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Patient not found' });
    }

    const [updatedPatient] = await pool.query('SELECT * FROM patients WHERE id = ?', [id]);
    res.json(updatedPatient[0]);
  } catch (err) {
    console.error('Error updating patient profile:', err.message);
    res.status(500).json({ message: 'Failed to update patient profile', error: err.message });
  }
});

// Update medical history entry
app.put('/patients/:id/medical-history/:historyId', async (req, res) => {
  const { id, historyId } = req.params;
  const { history } = req.body;

  if (!history) {
    return res.status(400).json({ message: 'Missing required field: history is required' });
  }

  try {
    const [result] = await pool.query(
      'UPDATE medical_history SET history = ? WHERE id = ? AND patient_id = ?',
      [history, historyId, id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Medical history entry not found' });
    }
    const [updatedEntry] = await pool.query('SELECT * FROM medical_history WHERE id = ?', [historyId]);
    res.json(updatedEntry[0]);
  } catch (err) {
    console.error('Error updating medical history:', err.message);
    res.status(500).json({ message: 'Failed to update medical history', error: err.message });
  }
});

// Delete medical history entry
app.delete('/patients/:id/medical-history/:historyId', async (req, res) => {
  const { id, historyId } = req.params;
  try {
    const [result] = await pool.query(
      'DELETE FROM medical_history WHERE id = ? AND patient_id = ?',
      [historyId, id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Medical history entry not found' });
    }
    res.status(204).send();
  } catch (err) {
    console.error('Error deleting medical history:', err.message);
    res.status(500).json({ message: 'Failed to delete medical history', error: err.message });
  }
});

// Fetch alerts for a caregiver's patients
app.get('/alerts', async (req, res) => {
  const { caregiver_id } = req.query;
  try {
    const [alerts] = await pool.query(`
      SELECT sa.*, p.name AS patient_name
      FROM safety_alerts sa
      JOIN patients p ON sa.patient_id = p.id
      WHERE p.caregiver_id = ?
      ORDER BY sa.timestamp DESC
    `, [caregiver_id]);
    res.json(alerts.map(alert => ({
      id: alert.id,
      type: 'Safety Alert',
      patient_name: alert.patient_name,
      time: new Date(alert.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
      message: alert.message,
    })));
  } catch (err) {
    console.error('Error fetching alerts:', err.message);
    res.status(500).json({ message: 'Failed to fetch alerts', error: err.message });
  }
});

// Update medication
app.put('/medications/:id', async (req, res) => {
  const { id } = req.params;
  const { dose, time, status } = req.body;

  if (!dose && !time && !status) {
    return res.status(400).json({ message: 'At least one field (dose, time, status) is required' });
  }

  try {
    const updates = {};
    if (dose) updates.dose = dose;
    if (time) updates.time = time;
    if (status) updates.status = status;

    const fields = Object.keys(updates).map(field => `${field} = ?`).join(', ');
    const values = Object.values(updates);

    const [result] = await pool.query(
      `UPDATE medications SET ${fields} WHERE id = ?`,
      [...values, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Medication not found' });
    }

    const [updatedMedication] = await pool.query('SELECT * FROM medications WHERE id = ?', [id]);
    res.json(updatedMedication[0]);
  } catch (err) {
    console.error('Error updating medication:', err.message);
    res.status(500).json({ message: 'Failed to update medication', error: err.message });
  }
});

// Delete medication
app.delete('/medications/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query('DELETE FROM medications WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Medication not found' });
    }
    res.status(204).send();
  } catch (err) {
    console.error('Error deleting medication:', err.message);
    res.status(500).json({ message: 'Failed to delete medication', error: err.message });
  }
});

// Schedules endpoints
app.get('/schedules', async (req, res) => {
  const { patient_id } = req.query;
  if (!patient_id) {
    return res.status(400).json({ message: 'patient_id is required' });
  }
  try {
    const [rows] = await pool.query('SELECT * FROM schedules WHERE patient_id = ?', [patient_id]);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching schedules:', err.message);
    res.status(500).json({ message: 'Failed to fetch schedules', error: err.message });
  }
});

app.post('/schedules', async (req, res) => {
  const { patient_id, time, task, medication_note, completed } = req.body;

  if (!patient_id || !time || !task) {
    return res.status(400).json({ message: 'Missing required fields: patient_id, time, and task are required' });
  }

  try {
    const [patient] = await pool.query('SELECT id FROM patients WHERE id = ?', [patient_id]);
    if (patient.length === 0) {
      return res.status(404).json({ message: 'Patient not found' });
    }

    const [result] = await pool.query(
      'INSERT INTO schedules (patient_id, time, task, medication_note, completed) VALUES (?, ?, ?, ?, ?)',
      [patient_id, time, task, medication_note || '', completed || false]
    );

    const [newSchedule] = await pool.query('SELECT * FROM schedules WHERE id = ?', [result.insertId]);
    res.status(201).json(newSchedule[0]);
  } catch (err) {
    console.error('Error adding schedule:', err.message);
    res.status(500).json({ message: 'Failed to add schedule', error: err.message });
  }
});

app.put('/schedules/:id', async (req, res) => {
  const { id } = req.params;
  const { time, task, medication_note, completed } = req.body;

  if (!time && !task && medication_note === undefined && completed === undefined) {
    return res.status(400).json({ message: 'At least one field (time, task, medication_note, completed) is required' });
  }

  try {
    const [schedule] = await pool.query('SELECT * FROM schedules WHERE id = ?', [id]);
    if (schedule.length === 0) {
      return res.status(404).json({ message: 'Schedule not found' });
    }

    const updates = {};
    if (time) updates.time = time;
    if (task) updates.task = task;
    if (medication_note !== undefined) updates.medication_note = medication_note;
    if (completed !== undefined) updates.completed = completed;

    const fields = Object.keys(updates).map(field => `${field} = ?`).join(', ');
    const values = Object.values(updates);

    const [result] = await pool.query(
      `UPDATE schedules SET ${fields} WHERE id = ?`,
      [...values, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Schedule not found' });
    }

    const [updatedSchedule] = await pool.query('SELECT * FROM schedules WHERE id = ?', [id]);
    res.json(updatedSchedule[0]);
  } catch (err) {
    console.error('Error updating schedule:', err.message);
    res.status(500).json({ message: 'Failed to update schedule', error: err.message });
  }
});

app.delete('/schedules/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query('DELETE FROM schedules WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Schedule not found' });
    }
    res.status(204).send();
  } catch (err) {
    console.error('Error deleting schedule:', err.message);
    res.status(500).json({ message: 'Failed to delete schedule', error: err.message });
  }
});

// Activities endpoints
app.get('/activities', async (req, res) => {
  const { patient_id } = req.query;
  if (!patient_id) {
    return res.status(400).json({ message: 'patient_id is required' });
  }
  try {
    const [rows] = await pool.query('SELECT * FROM activities WHERE patient_id = ? ORDER BY timestamp DESC', [patient_id]);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching activities:', err.message);
    res.status(500).json({ message: 'Failed to fetch activities', error: err.message });
  }
});

app.post('/activities', async (req, res) => {
  const { patient_id, activity, timestamp } = req.body;

  if (!patient_id || !activity || !timestamp) {
    return res.status(400).json({ message: 'Missing required fields: patient_id, activity, and timestamp are required' });
  }

  try {
    const parsedTimestamp = new Date(timestamp);
    if (isNaN(parsedTimestamp.getTime())) {
      return res.status(400).json({ message: 'Invalid timestamp format' });
    }
    const formattedTimestamp = parsedTimestamp.toISOString().slice(0, 19).replace('T', ' ');

    const [patient] = await pool.query('SELECT id FROM patients WHERE id = ?', [patient_id]);
    if (patient.length === 0) {
      return res.status(404).json({ message: 'Patient not found' });
    }

    const [result] = await pool.query(
      'INSERT INTO activities (patient_id, activity, timestamp) VALUES (?, ?, ?)',
      [patient_id, activity, formattedTimestamp]
    );

    const [newActivity] = await pool.query('SELECT * FROM activities WHERE id = ?', [result.insertId]);
    res.status(201).json(newActivity[0]);
  } catch (err) {
    console.error('Error adding activity:', err.message);
    res.status(500).json({ message: 'Failed to add activity', error: err.message });
  }
});

// Flashbacks endpoints
app.get('/flashbacks', async (req, res) => {
  const { patient_id } = req.query;
  if (!patient_id) {
    return res.status(400).json({ message: 'patient_id is required' });
  }
  try {
    const [rows] = await pool.query('SELECT * FROM flashbacks WHERE patient_id = ? ORDER BY created_at DESC', [patient_id]);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching flashbacks:', err.message);
    res.status(500).json({ message: 'Failed to fetch flashbacks', error: err.message });
  }
});

app.post('/flashbacks', upload.single('image'), async (req, res) => {
  const { patient_id, alt, caption, details } = req.body;

  if (!patient_id || !alt || !caption) {
    return res.status(400).json({ message: 'Missing required fields: patient_id, alt, and caption are required' });
  }

  if (!req.file) {
    return res.status(400).json({ message: 'No image file uploaded' });
  }

  try {
    const [patient] = await pool.query('SELECT id FROM patients WHERE id = ?', [patient_id]);
    if (patient.length === 0) {
      return res.status(404).json({ message: 'Patient not found' });
    }

    const src = `http://localhost:3001/uploads/${req.file.filename}`;

    const [result] = await pool.query(
      'INSERT INTO flashbacks (patient_id, src, alt, caption, details) VALUES (?, ?, ?, ?, ?)',
      [patient_id, src, alt, caption, details || '']
    );

    const [newFlashback] = await pool.query('SELECT * FROM flashbacks WHERE id = ?', [result.insertId]);
    res.status(201).json(newFlashback[0]);
  } catch (err) {
    console.error('Error adding flashback:', err.message);
    res.status(500).json({ message: 'Failed to add flashback', error: err.message });
  }
});

app.delete('/flashbacks/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [flashback] = await pool.query('SELECT src FROM flashbacks WHERE id = ?', [id]);
    if (flashback.length === 0) {
      return res.status(404).json({ message: 'Flashback not found' });
    }

    const filePath = path.join(__dirname, 'uploads', path.basename(flashback[0].src));
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    const [result] = await pool.query('DELETE FROM flashbacks WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Flashback not found' });
    }
    res.status(204).send();
  } catch (err) {
    console.error('Error deleting flashback:', err.message);
    res.status(500).json({ message: 'Failed to delete flashback', error: err.message });
  }
});

// Messages endpoints
app.get('/messages', async (req, res) => {
  const { patient_id } = req.query;
  if (!patient_id) {
    return res.status(400).json({ message: 'patient_id is required' });
  }
  try {
    const [rows] = await pool.query('SELECT * FROM messages WHERE patient_id = ?', [patient_id]);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching messages:', err.message);
    res.status(500).json({ message: 'Failed to fetch messages', error: err.message });
  }
});

app.post('/messages', async (req, res) => {
  const { patient_id, sender, content, type, timestamp } = req.body;

  // Validate request body
  if (!patient_id || !sender || !content || !type || !timestamp) {
    console.error('Missing required fields in /messages request:', { patient_id, sender, content, type, timestamp });
    return res.status(400).json({ message: 'Missing required fields: patient_id, sender, content, type, and timestamp are required' });
  }

  // Validate type
  if (!['text', 'voice'].includes(type)) {
    console.error('Invalid message type:', type);
    return res.status(400).json({ message: "Invalid message type. Must be 'text' or 'voice'" });
  }

  try {
    // Validate patient_id exists in patients table
    const [patient] = await pool.query('SELECT id FROM patients WHERE id = ?', [patient_id]);
    if (patient.length === 0) {
      console.error('Patient not found for patient_id:', patient_id);
      return res.status(404).json({ message: 'Patient not found' });
    }

    // Parse and format the timestamp to MySQL DATETIME format (YYYY-MM-DD HH:mm:ss)
    const parsedTimestamp = new Date(timestamp);
    if (isNaN(parsedTimestamp.getTime())) {
      throw new Error('Invalid timestamp format');
    }
    const formattedTimestamp = parsedTimestamp.toISOString().slice(0, 19).replace('T', ' '); // e.g., "2025-05-12 12:34:56"

    // Insert the message into the messages table
    await pool.query(
      'INSERT INTO messages (patient_id, sender, content, type, timestamp) VALUES (?, ?, ?, ?, ?)',
      [patient_id, sender, content, type, formattedTimestamp]
    );

    // Update the patient's last_activity
    const lastActivity = `Sent a message at ${new Date(formattedTimestamp).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
    })}`;
    await pool.query('UPDATE patients SET last_activity = ? WHERE id = ?', [lastActivity, patient_id]);

    res.status(201).json({ message: 'Message sent' });
  } catch (err) {
    console.error('Error sending message:', err.message, err.stack);
    res.status(500).json({ message: 'Failed to send message', error: err.message });
  }
});

// Emergency Contacts endpoints
app.get('/emergency-contacts', async (req, res) => {
  const { patient_id } = req.query;
  if (!patient_id) {
    return res.status(400).json({ message: 'patient_id is required' });
  }
  try {
    const [rows] = await pool.query('SELECT * FROM emergency_contacts WHERE patient_id = ?', [patient_id]);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching emergency contacts:', err.message);
    res.status(500).json({ message: 'Failed to fetch emergency contacts', error: err.message });
  }
});

app.post('/emergency-contacts', async (req, res) => {
  const { patient_id, name, phone } = req.body;
  if (!patient_id || !name || !phone) {
    return res.status(400).json({ message: 'Missing required fields: patient_id, name, and phone are required' });
  }
  try {
    await pool.query(
      'INSERT INTO emergency_contacts (patient_id, name, phone) VALUES (?, ?, ?)',
      [patient_id, name, phone]
    );
    const lastActivity = `Added emergency contact at ${new Date().toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
    })}`;
    await pool.query('UPDATE patients SET last_activity = ? WHERE id = ?', [lastActivity, patient_id]);
    res.status(201).json({ message: 'Emergency contact added' });
  } catch (err) {
    console.error('Error adding emergency contact:', err.message);
    res.status(500).json({ message: 'Failed to add emergency contact', error: err.message });
  }
});

// Safety Alert endpoint
app.post('/safety-alert', async (req, res) => {
  const { patient_id, message, timestamp } = req.body;
  if (!patient_id || !message || !timestamp) {
    return res.status(400).json({ message: 'Missing required fields: patient_id, message, and timestamp are required' });
  }
  try {
    await pool.query(
      'INSERT INTO safety_alerts (patient_id, message, timestamp) VALUES (?, ?, ?)',
      [patient_id, message, timestamp]
    );
    const lastActivity = `Sent safety alert at ${new Date(timestamp).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
    })}`;
    await pool.query('UPDATE patients SET last_activity = ? WHERE id = ?', [lastActivity, patient_id]);
    res.status(201).json({ message: 'Safety alert sent' });
  } catch (err) {
    console.error('Error sending safety alert:', err.message);
    res.status(500).json({ message: 'Failed to send safety alert', error: err.message });
  }
});

// Emergency Audio endpoint
app.post('/emergency-audio', async (req, res) => {
  const { patient_id, content, type, timestamp } = req.body;

  if (!patient_id || !content || !type || !timestamp) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  try {
    await pool.query(
      'INSERT INTO messages (patient_id, sender, content, type, timestamp) VALUES (?, ?, ?, ?, ?)',
      [patient_id, 'Patient', content, type, timestamp]
    );
    const lastActivity = `Recorded emergency audio at ${new Date(timestamp).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
    })}`;
    await pool.query('UPDATE patients SET last_activity = ? WHERE id = ?', [lastActivity, patient_id]);
    res.status(201).json({ message: 'Emergency audio note sent' });
  } catch (err) {
    console.error('Error sending emergency audio:', err.message);
    res.status(500).json({ message: 'Failed to send emergency audio', error: err.message });
  }
});

// Mood Entries endpoints
app.get('/mood-entries', async (req, res) => {
  const { patient_id } = req.query;
  if (!patient_id) {
    return res.status(400).json({ message: 'patient_id is required' });
  }
  try {
    const [rows] = await pool.query(
      'SELECT date, time, score, tags, notes FROM mood_entries WHERE patient_id = ? ORDER BY created_at DESC',
      [patient_id]
    );
    res.json(rows);
  } catch (err) {
    console.error('Error fetching mood entries:', err.message);
    res.status(500).json({ message: 'Failed to fetch mood entries', error: err.message });
  }
});

app.post('/mood-entries', async (req, res) => {
  const { patient_id, date, time, score, tags, notes } = req.body;
  if (!patient_id || !date || !time || !score) {
    return res.status(400).json({ message: 'Missing required fields: patient_id, date, time, and score are required' });
  }
  try {
    await pool.query(
      'INSERT INTO mood_entries (patient_id, date, time, score, tags, notes) VALUES (?, ?, ?, ?, ?, ?)',
      [patient_id, date, time, score, tags, notes]
    );
    const lastActivity = `Submitted mood entry at ${new Date().toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
    })}`;
    await pool.query('UPDATE patients SET last_activity = ? WHERE id = ?', [lastActivity, patient_id]);
    res.status(201).json({ message: 'Mood entry saved' });
  } catch (err) {
    console.error('Error saving mood entry:', err.message);
    res.status(500).json({ message: 'Failed to save mood entry', error: err.message });
  }
});

// Last Activity endpoint
app.get('/last-activity', async (req, res) => {
  const { patient_id } = req.query;
  if (!patient_id) {
    return res.status(400).json({ message: 'patient_id is required' });
  }
  try {
    const [rows] = await pool.query('SELECT last_activity FROM patients WHERE id = ?', [patient_id]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Patient not found' });
    }
    const lastActivity = rows[0].last_activity || 'No recent activity recorded';
    res.json({ last_activity: lastActivity });
  } catch (err) {
    console.error('Error fetching last activity:', err.message);
    res.status(500).json({ message: 'Failed to fetch last activity', error: err.message });
  }
});

// Update emergency contact
app.put('/emergency-contacts/:id', async (req, res) => {
  const { id } = req.params;
  const { name, phone } = req.body;
  if (!name || !phone) {
    return res.status(400).json({ message: 'Missing required fields: name and phone are required' });
  }
  try {
    const [result] = await pool.query(
      'UPDATE emergency_contacts SET name = ?, phone = ? WHERE id = ?',
      [name, phone, id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Emergency contact not found' });
    }
    const lastActivity = `Updated emergency contact at ${new Date().toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
    })}`;
    await pool.query('UPDATE patients SET last_activity = ? WHERE id = (SELECT patient_id FROM emergency_contacts WHERE id = ?)', [lastActivity, id]);
    res.status(200).json({ message: 'Emergency contact updated' });
  } catch (err) {
    console.error('Error updating emergency contact:', err.message);
    res.status(500).json({ message: 'Failed to update emergency contact', error: err.message });
  }
});

// Delete emergency contact
app.delete('/emergency-contacts/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [contact] = await pool.query('SELECT patient_id FROM emergency_contacts WHERE id = ?', [id]);
    if (contact.length === 0) {
      return res.status(404).json({ message: 'Emergency contact not found' });
    }
    const patient_id = contact[0].patient_id;
    const [result] = await pool.query('DELETE FROM emergency_contacts WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Emergency contact not found' });
    }
    const lastActivity = `Deleted emergency contact at ${new Date().toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
    })}`;
    await pool.query('UPDATE patients SET last_activity = ? WHERE id = ?', [lastActivity, patient_id]);
    res.status(200).json({ message: 'Emergency contact deleted' });
  } catch (err) {
    console.error('Error deleting emergency contact:', err.message);
    res.status(500).json({ message: 'Failed to delete emergency contact', error: err.message });
  }
});

// Fetch messages for a caregiver's patients
app.get('/caregiver-messages', async (req, res) => {
  const { caregiver_id } = req.query;
  if (!caregiver_id) {
    return res.status(400).json({ message: 'caregiver_id is required' });
  }
  try {
    const [messages] = await pool.query(`
      SELECT m.*, p.name AS patient_name, p.profile_picture AS patient_picture
      FROM messages m
      JOIN patients p ON m.patient_id = p.id
      WHERE p.caregiver_id = ?
      ORDER BY m.timestamp DESC
    `, [caregiver_id]);
    res.json(messages.map(message => ({
      id: message.id,
      patient_id: message.patient_id,
      patient_name: message.patient_name,
      patient_picture: message.patient_picture,
      sender: message.sender,
      content: message.content,
      type: message.type,
      timestamp: message.timestamp,
    })));
  } catch (err) {
    console.error('Error fetching caregiver messages:', err.message);
    res.status(500).json({ message: 'Failed to fetch caregiver messages', error: err.message });
  }
});

// Upload profile picture for a patient
app.post('/patients/:id/upload-profile-picture', upload.single('profilePicture'), async (req, res) => {
  const { id } = req.params;

  if (!req.file) {
    console.error('No file uploaded for profile picture');
    return res.status(400).json({ message: 'No file uploaded' });
  }

  try {
    const profilePictureUrl = `http://localhost:3001/uploads/${req.file.filename}`;
    await pool.query(
      'UPDATE patients SET profile_picture = ? WHERE id = ?',
      [profilePictureUrl, id]
    );

    const lastActivity = `Updated profile picture at ${new Date().toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
    })}`;
    await pool.query('UPDATE patients SET last_activity = ? WHERE id = ?', [lastActivity, id]);

    res.status(200).json({ message: 'Profile picture uploaded successfully', profilePicture: profilePictureUrl });
  } catch (err) {
    console.error('Error uploading profile picture:', err.message, err.stack);
    res.status(500).json({ message: 'Failed to upload profile picture', error: err.message });
  }
});

// Start the server only after database initialization
(async () => {
  try {
    await initializeDatabase();
    app.listen(3001, () => {
      console.log('Server running on port 3001');
    });
  } catch (err) {
    console.error('Failed to initialize database and start server:', err.message);
    process.exit(1);
  }
})();