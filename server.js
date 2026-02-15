const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// Configuration
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'mySuperUltraSecretKey_2026';
const JSONBIN_API_KEY = '6990e76cd0ea881f40bacfeb';
const JSONBIN_BIN_ID = '$2a$10$f8wZt4ClRVU5QfRYapHa3.9OzEo0R4jrX0gR3shYdOr5BZUNmJJwW';
const JSONBIN_URL = `https://api.jsonbin.io/v3/b/${JSONBIN_BIN_ID}`;

// Initialize users array in JSONBin (run once)
async function initializeJsonBin() {
    try {
        const response = await axios.get(JSONBIN_URL, {
            headers: {
                'X-Master-Key': JSONBIN_API_KEY
            }
        });
        console.log('✓ JSONBin connected successfully');
        return response.data.record.users || [];
    } catch (error) {
        if (error.response?.status === 404) {
            console.log('Creating new JSONBin bin for users...');
            try {
                await axios.post('https://api.jsonbin.io/v3/b', 
                    { users: [] },
                    {
                        headers: {
                            'X-Master-Key': JSONBIN_API_KEY,
                            'Content-Type': 'application/json'
                        }
                    }
                );
                console.log('✓ JSONBin bin created successfully');
                return [];
            } catch (createError) {
                console.error('Error creating JSONBin bin:', createError.message);
                throw createError;
            }
        }
        console.error('Error initializing JSONBin:', error.message);
        throw error;
    }
}

// Get all users from JSONBin
async function getAllUsers() {
    try {
        const response = await axios.get(JSONBIN_URL, {
            headers: {
                'X-Master-Key': JSONBIN_API_KEY
            }
        });
        return response.data.record.users || [];
    } catch (error) {
        console.error('Error fetching users from JSONBin:', error.message);
        return [];
    }
}

// Save users to JSONBin
async function saveUsersToJsonBin(users) {
    try {
        await axios.put(JSONBIN_URL,
            { users },
            {
                headers: {
                    'X-Master-Key': JSONBIN_API_KEY,
                    'Content-Type': 'application/json'
                }
            }
        );
        console.log('✓ Users saved to JSONBin');
        return true;
    } catch (error) {
        console.error('Error saving users to JSONBin:', error.message);
        throw error;
    }
}

// Validation functions
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function isValidPassword(password) {
    return password && password.length >= 8;
}

// ==================== SIGNUP ENDPOINT ====================
app.post('/api/signup', async (req, res) => {
    try {
        const { fullName, email, password } = req.body;

        // Validation
        if (!fullName || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Please provide all required fields'
            });
        }

        if (!isValidEmail(email)) {
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid email address'
            });
        }

        if (!isValidPassword(password)) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long'
            });
        }

        if (fullName.trim().length < 2) {
            return res.status(400).json({
                success: false,
                message: 'Full name must be at least 2 characters'
            });
        }

        // Get all users from JSONBin
        const users = await getAllUsers();

        // Check if user already exists
        const userExists = users.find(user => user.email.toLowerCase() === email.toLowerCase());
        if (userExists) {
            return res.status(409).json({
                success: false,
                message: 'Email address already registered'
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const newUser = {
            id: Date.now().toString(),
            fullName: fullName.trim(),
            email: email.toLowerCase(),
            password: hashedPassword,
            createdAt: new Date().toISOString(),
            lastLogin: null,
            isActive: true
        };

        // Add user to array
        users.push(newUser);

        // Save to JSONBin
        await saveUsersToJsonBin(users);

        // Generate JWT token
        const token = jwt.sign(
            { userId: newUser.id, email: newUser.email },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        console.log(`✓ New user registered: ${email}`);

        res.status(201).json({
            success: true,
            message: 'Account created successfully',
            token,
            user: {
                id: newUser.id,
                fullName: newUser.fullName,
                email: newUser.email
            }
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred during signup. Please try again.'
        });
    }
});

// ==================== LOGIN ENDPOINT ====================
app.post('/api/login', async (req, res) => {
    try {
        const { email, password, remember } = req.body;

        // Validation
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Please provide email and password'
            });
        }

        if (!isValidEmail(email)) {
            return res.status(400).json({
                success: false,
                message: 'Please provide a valid email address'
            });
        }

        // Get all users from JSONBin
        const users = await getAllUsers();

        // Find user by email
        const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        if (!user.isActive) {
            return res.status(403).json({
                success: false,
                message: 'This account has been deactivated'
            });
        }

        // Compare passwords
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Update last login
        const userIndex = users.findIndex(u => u.id === user.id);
        users[userIndex].lastLogin = new Date().toISOString();
        await saveUsersToJsonBin(users);

        // Generate JWT token
        const expiresIn = remember ? '30d' : '7d';
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn }
        );

        console.log(`✓ User logged in: ${email}`);

        res.status(200).json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                fullName: user.fullName,
                email: user.email
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred during login. Please try again.'
        });
    }
});

// ==================== GET USER PROFILE ====================
app.get('/api/user/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const users = await getAllUsers();
        const user = users.find(u => u.id === id);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.status(200).json({
            success: true,
            user: {
                id: user.id,
                fullName: user.fullName,
                email: user.email,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin
            }
        });

    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred'
        });
    }
});

// ==================== UPDATE USER PROFILE ====================
app.put('/api/user/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { fullName } = req.body;

        if (!fullName || fullName.trim().length < 2) {
            return res.status(400).json({
                success: false,
                message: 'Full name must be at least 2 characters'
            });
        }

        const users = await getAllUsers();
        const userIndex = users.findIndex(u => u.id === id);

        if (userIndex === -1) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        users[userIndex].fullName = fullName.trim();
        await saveUsersToJsonBin(users);

        console.log(`✓ User profile updated: ${id}`);

        res.status(200).json({
            success: true,
            message: 'Profile updated successfully',
            user: {
                id: users[userIndex].id,
                fullName: users[userIndex].fullName,
                email: users[userIndex].email
            }
        });

    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred'
        });
    }
});

// ==================== CHANGE PASSWORD ====================
app.post('/api/change-password', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.user;
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Please provide current and new password'
            });
        }

        if (!isValidPassword(newPassword)) {
            return res.status(400).json({
                success: false,
                message: 'New password must be at least 8 characters'
            });
        }

        if (currentPassword === newPassword) {
            return res.status(400).json({
                success: false,
                message: 'New password must be different from current password'
            });
        }

        const users = await getAllUsers();
        const userIndex = users.findIndex(u => u.id === userId);

        if (userIndex === -1) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Verify current password
        const passwordMatch = await bcrypt.compare(currentPassword, users[userIndex].password);

        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        users[userIndex].password = hashedPassword;
        await saveUsersToJsonBin(users);

        console.log(`✓ Password changed for user: ${userId}`);

        res.status(200).json({
            success: true,
            message: 'Password changed successfully'
        });

    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred'
        });
    }
});

// ==================== MIDDLEWARE ====================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access token required'
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: 'Invalid or expired token'
            });
        }
        req.user = user;
        next();
    });
}

// ==================== ERROR HANDLING ====================
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        success: false,
        message: 'An unexpected error occurred'
    });
});

// ==================== 404 HANDLER ====================
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Endpoint not found'
    });
});

// ==================== START SERVER ====================
app.listen(PORT, async () => {
    try {
        await initializeJsonBin();
        console.log(`\n🚀 Shineal Host Server running on http://localhost:${PORT}`);
        console.log(`📊 JSONBin Bin ID: ${JSONBIN_BIN_ID}`);
        console.log(`\nAvailable endpoints:`);
        console.log(`  POST   /api/signup              - Register new user`);
        console.log(`  POST   /api/login               - Login user`);
        console.log(`  GET    /api/user/:id            - Get user profile`);
        console.log(`  PUT    /api/user/:id            - Update user profile`);
        console.log(`  POST   /api/change-password     - Change password\n`);
    } catch (error) {
        console.error('Failed to start server:', error.message);
        process.exit(1);
    }
});

module.exports = app;
