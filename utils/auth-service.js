const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// Hash a password
const hashedPassword = async (password) => {
    try {
        const saltRounds = 10; // Cost factor for hashing
        const hashed = await bcrypt.hash(password, saltRounds);
        return hashed; // Return the hashed password
    } catch (error) {
        throw new Error("Error hashing password: " + error.message);
    }
};

// Compare a password with a hashed password
const comparePassword = async (password, hashed) => {
    try {
        const match = await bcrypt.compare(password, hashed);
        return match; // Returns true if passwords match, false otherwise
    } catch (error) {
        throw new Error("Error comparing passwords: " + error.message);
    }
};

// Generate a JWT
const generateToken = (user) => {
    try {
        const payload = {
             ...user
        };
        const secretKey = process.env.JWT_SECRET_KEY || "kGPsIV7TLJZ2alXGqVOJlxg0Zhlgz6gixiBzD6rpebEc9YqT3RKQZaic144EsIkf"; // Use environment variable for secret
        const options = { expiresIn: '7d' }; // Token expiration time
        const token = jwt.sign(payload, secretKey, options);
        return token; // Return the generated token
    } catch (error) {
        throw new Error("Error generating token: " + error.message);
    }
};



module.exports = {
    hashedPassword,
    comparePassword,
    generateToken,
};
