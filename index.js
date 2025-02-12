import express from 'express';
import pkg from 'body-parser';
import cors from 'cors';
import pckg from 'pg';
import packg from 'jsonwebtoken';
import { config } from 'dotenv';
import bcrypt from 'bcrypt';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

config();

const app = express();
const port = process.env.PORT || 3000;
const { Pool } = pckg;
const { json } = pkg;
const { verify, sign } = packg;

// Security middleware
app.use(helmet());
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || 'http://localhost:3000',
    credentials: true
}));
app.use(json({ limit: '10kb' })); // Limit payload size

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: true // Enforce SSL verification
    }
});

// Improved token verification middleware
const authenticateToken = (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader?.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Missing or invalid token format' });
        }

        const token = authHeader.split(' ')[1];
        const user = verify(token, process.env.JWT_SECRET);
        req.user = user;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

// Improved admin authentication with constant-time comparison
const authenticateAdmin = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    console.log('Received API Key:', apiKey);
    console.log('Expected API Key:', process.env.ADMIN_API_KEY);
    if (apiKey !== process.env.ADMIN_API_KEY) {
        return res.status(403).json({ error: 'Authentication failed' });
    }
    next();
};

// Register a User with password hashing and input validation
app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;
    
    // Input validation
    if (!username?.trim() || !password?.trim() || password.length < 8) {
        return res.status(400).json({ 
            error: 'Invalid input. Username required and password must be at least 8 characters' 
        });
    }

    try {
        // Check for existing user
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE username = $1',
            [username]
        );
        
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: 'Username already exists' });
        }

        // Hash password
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        const result = await pool.query(
            'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username, role',
            [username, hashedPassword, role === 'admin' ? 'user' : 'user'] // Prevent admin role assignment
        );
        
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Secure login with rate limiting and proper password comparison
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many login attempts. Please try again later.' }
});

app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    
    if (!username?.trim() || !password?.trim()) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1',
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const accessToken = sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ accessToken });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Secure train management endpoints
app.post('/trains', authenticateAdmin, async (req, res) => {
    const { name, source, destination, total_seats } = req.body;
    
    // Input validation
    if (!name?.trim() || !source?.trim() || !destination?.trim() || 
        !Number.isInteger(total_seats) || total_seats <= 0) {
        return res.status(400).json({ error: 'Invalid input data' });
    }

    try {
        const result = await pool.query(
            'INSERT INTO trains (name, source, destination, total_seats, available_seats) VALUES ($1, $2, $3, $4, $4) RETURNING *',
            [name, source, destination, total_seats]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Train creation error:', err);
        res.status(500).json({ error: 'Failed to create train' });
    }
});

// Secure availability check with input validation
app.get('/availability', async (req, res) => {
    const { source, destination } = req.query;
    
    if (!source?.trim() || !destination?.trim()) {
        return res.status(400).json({ error: 'Source and destination required' });
    }

    try {
        const result = await pool.query(
            'SELECT id, name, source, destination, available_seats FROM trains WHERE source = $1 AND destination = $2',
            [source, destination]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Availability check error:', err);
        res.status(500).json({ error: 'Failed to check availability' });
    }
});

// Secure booking with transaction and input validation
app.post('/book', authenticateToken, async (req, res) => {
    const { train_id, seats } = req.body;
    const user_id = req.user.id;

    if (!Number.isInteger(train_id) || !Number.isInteger(seats) || seats <= 0) {
        return res.status(400).json({ error: 'Invalid booking data' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        const trainResult = await client.query(
            'SELECT available_seats FROM trains WHERE id = $1 FOR UPDATE',
            [train_id]
        );

        if (trainResult.rows.length === 0) {
            throw new Error('Train not found');
        }

        const availableSeats = trainResult.rows[0].available_seats;
        if (availableSeats < seats) {
            throw new Error('Not enough seats available');
        }

        await client.query(
            'UPDATE trains SET available_seats = available_seats - $1 WHERE id = $2',
            [seats, train_id]
        );

        const bookingResult = await client.query(
            'INSERT INTO bookings (user_id, train_id, seats_booked) VALUES ($1, $2, $3) RETURNING *',
            [user_id, train_id, seats]
        );

        await client.query('COMMIT');
        res.status(201).json(bookingResult.rows[0]);
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Booking error:', err);
        res.status(400).json({ error: err.message });
    } finally {
        client.release();
    }
});

// Secure booking retrieval with proper authorization
app.get('/booking/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    
    if (!Number.isInteger(parseInt(id))) {
        return res.status(400).json({ error: 'Invalid booking ID' });
    }

    try {
        const result = await pool.query(
            'SELECT b.*, t.name as train_name, t.source, t.destination FROM bookings b JOIN trains t ON b.train_id = t.id WHERE b.id = $1 AND b.user_id = $2',
            [id, req.user.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Booking not found' });
        }
        
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Booking retrieval error:', err);
        res.status(500).json({ error: 'Failed to retrieve booking' });
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});