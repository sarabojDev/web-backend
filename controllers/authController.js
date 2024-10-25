const asyncHandler = require("../middleware/asyncHandler");
const { __AUTH_BASE_USERS_COLLECTION, __AUTH_BASE_USERS_DOC } = require("../config/db");
const { query, where, getCountFromServer, addDoc, getDocs, updateDoc, doc, getDoc, Timestamp } = require("firebase/firestore");
const { hashedPassword, comparePassword, generateToken } = require("../utils/auth-service");
const _lodash = require("lodash");
const crypto = require("crypto");
const jwt = require('jsonwebtoken')


const registerUser = asyncHandler(async (req, res) => {
    try {
        // Extract user data from the request body
        let { username, password, email } = req.body;
        username = _lodash.trim(username);
        password = _lodash.trim(password);
        email = _lodash.trim(email);



        // Check if the user already exists
        const __CHECK_EXITS_USER_QUERY = query(__AUTH_BASE_USERS_COLLECTION, where("emailAddress", "==", email));
        const __IS_USER_REGISTER = await getCountFromServer(__CHECK_EXITS_USER_QUERY);

        // Check the count of existing users
        if (__IS_USER_REGISTER.data().count > 0) {
            const error = new Error("User already registered")
            error.statusCode = 400
            throw error
        }

        const hashPass = await hashedPassword(password);

        // Add new user to the collection
        await addDoc(__AUTH_BASE_USERS_COLLECTION, {
            emailAddress: email,
            password: hashPass,
            username,
            profile: "",
            software: ["hrms"],
            isActive: true,
            resetPasswordToken: null,
            isPasswordReset: false,
            registerOn: new Date()
        });

        // Respond with success
        res.status(201).json({ message: 'User registered successfully', status: true });
    } catch (err) {
        throw err
    }
});


const loginUser = asyncHandler(async (req, res) => {
    try {
        const { email, password } = req.body;
        // Validate input
        if (!email || !password) {
            return res.status(400).json({ status: false, message: "Email and password are required." });
        }

        // Fetch user from database
        const __CHECK_EXITS_USER_QUERY = query(__AUTH_BASE_USERS_COLLECTION, where("emailAddress", "==", email));
        const __IS_USER_REGISTER = await getDocs(__CHECK_EXITS_USER_QUERY);
        const user = __IS_USER_REGISTER.docs[0] ? { ...__IS_USER_REGISTER.docs[0].data(), id: __IS_USER_REGISTER.docs[0].id } : null;

        if (!user) {
            return res.status(401).json({ status: false, message: "Invalid email or password." });
        }

        // Compare the provided password with the stored hashed password
        const isMatch = await comparePassword(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ status: false, message: "Invalid email or password." });
        }

        // Generate a JWT
        user.password = undefined
        user.isPasswordReset = undefined
        user.resetTokenExpiration = undefined
        user.resetPasswordToken = undefined

        const token = generateToken(user);

        // Set the cookie
        res.cookie('auth_token', token, {
            httpOnly: true, // Helps mitigate XSS attacks
            secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
            path: '/' // Cookie is accessible on all routes
        });

        // Respond with user info (excluding password)
        res.status(200).json({
            status: true,
            message: "Login successful",
            user: {
                ...user
                // Add any other user details you want to return
            },
        });
    } catch (err) {
        console.error(err); // Log the error for debugging
        res.status(500).json({ status: false, message: "Internal server error." }); // Handle unexpected errors
    }
});

const forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body;

    try {
        // Validate input
        if (!email) {
            const error = new Error("Email is required.")
            error.statusCode = 401
            throw error
        }

        const __CHECK_EXITS_USER_QUERY = query(__AUTH_BASE_USERS_COLLECTION, where("emailAddress", "==", email));
        const __IS_USER_REGISTER = await getDocs(__CHECK_EXITS_USER_QUERY);
        const user = __IS_USER_REGISTER.docs[0] ? { ...__IS_USER_REGISTER.docs[0].data(), id: __IS_USER_REGISTER.docs[0].id } : null

        if (!user) {
            const error = new Error("User not found.")
            error.statusCode = 404
            throw error
        }

        // Generate a reset token

        const resetToken = crypto.randomBytes(32).toString('hex');
        const expirationTime = Date.now() + 3600000; // Token valid for 1 hour



        // Save the reset token and its expiration time in the database (e.g., with a timestamp)
        await updateDoc(__AUTH_BASE_USERS_DOC(user.id), {
            resetPasswordToken: resetToken,
            isPasswordReset: true,
            resetTokenExpiration: new Date(expirationTime),
        })

        // Create a reset link
        const resetLink = `${process.env.FRONTENT_URL}reset-password/${resetToken}`;

        const __sendEmail = await fetch('https://script.google.com/macros/s/AKfycbz5G2TA0EHfbooMF8ktIzq6HkwbsMXlZBYSo0waAtSy347tOJZLV__EH71elgHIIHUcAw/exec', {
            method: "POST",
            body: JSON.stringify({
                username: user.username,
                url: resetLink,
                email:user.emailAddress
            })
        })
        const sendEmailRes = await __sendEmail.json();

        if (sendEmailRes.status) {
            res.status(200).json({ status: true, message: "Password reset link has been sent to your email." });
        } else {
            const error = new Error("User not found.")
            error.statusCode = 404
            throw error
        }
        // Send the email

    } catch (error) {
        throw error
    }
})


const resetPassword = asyncHandler(async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        // Validate input
        if (!token || !newPassword) {
            const error = new Error('Token and new password are required.');
            error.statusCode = 401
            throw error
        }

        // Find user by reset token
        const __CHECK_USER_QUERY = query(__AUTH_BASE_USERS_COLLECTION, where("isPasswordReset", "==", true), where("resetPasswordToken", "==", token), where("resetTokenExpiration", ">=", Timestamp.now()));
        const __USER = await getDocs(__CHECK_USER_QUERY);
        const user = __USER.docs[0] ? { ...__USER.docs[0].data(), id: __USER.docs[0].id } : null;

        if (!user) {
            const error = new Error('Invalid or expired token.');
            error.statusCode = 400
            throw error
        }

        // Update the user's password (make sure to hash it)
        const hashedPass = await hashedPassword(newPassword); // Implement this function to hash passwords
        await updateDoc(__AUTH_BASE_USERS_DOC(user.id), {
            password: hashedPass,
            resetPasswordToken: null, // Invalidate the token
            resetTokenExpiration: null, // Clear expiration
            isPasswordReset: false
        });

        res.status(200).json({ status: true, message: "Password has been reset successfully." });
    } catch (error) {
        throw error
    }
});

const refreshLoginUser = asyncHandler(async (req, res) => {
    try {
        const __refreshToken = req.cookies.auth_token;

        // Check if the token is present
        if (!__refreshToken) {
            return res.status(401).json({ status: false, message: "No token provided." });
        }

        // Verify the token
        const decoded = jwt.verify(__refreshToken, process.env.JWT_SECRET_KEY); // Replace with your secret

        const __CHECK_DOC = await getDoc(__AUTH_BASE_USERS_DOC(decoded.id));
        if (__CHECK_DOC.exists()) {
            const __user_data = __CHECK_DOC.data();
            const { emailAddress } = __user_data;
            __user_data.password = undefined
            __user_data.isPasswordReset = undefined
            __user_data.resetTokenExpiration = undefined
            __user_data.resetPasswordToken = undefined

            if (emailAddress === decoded.emailAddress) {
                res.status(200).json({
                    status: true,
                    message: "Token is valid.",
                    user: { // Customize the user object as per your application
                        ...__user_data,
                        id: __CHECK_DOC.id
                        // Add other user properties as needed
                    },
                });
            } else {
                return res.status(403).json({ status: false, message: "Invalid token." });
            }
        } else {
            return res.status(403).json({ status: false, message: "Invalid token." });
        }


    } catch (error) {
        console.error("Token verification error:", error);
        // Handle token expiration or invalid token
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ status: false, message: "Token expired." });
        } else {
            return res.status(403).json({ status: false, message: "Invalid token." });
        }
    }
});




module.exports = {
    registerUser,
    loginUser,
    forgotPassword,
    resetPassword,
    refreshLoginUser
};
