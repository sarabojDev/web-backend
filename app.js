const express = require("express");
const cors = require("cors");
const errorHandler = require("./middleware/errorHandler");
const authRouter = require("./routes/authRouter");
const dotenv = require("dotenv");
const path = require("path");
const cookieParser = require("cookie-parser");

const app = express();

// Load environment variables from .env file
dotenv.config({ path: path.join(__dirname, 'config', '.env') });

// CORS configuration
const corsOptions = {
    origin: ['http://localhost:3000', 'http://localhost:5173'], // List of allowed origins
    credentials: true, // Allow credentials (cookies)
};

// Middleware
app.use(cors(corsOptions)); // Use configured CORS options
// app.options('*', cors(corsOptions));
app.use(express.json()); // Middleware to parse JSON
app.use(cookieParser()); // Middleware to handle cookies

// Routers
app.use("/api/v1/auth", authRouter);

// Error handling middleware
app.use(errorHandler);

// Export the app
module.exports = app;
