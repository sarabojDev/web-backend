const express = require("express");
const { registerUser, loginUser, forgotPassword, resetPassword } = require("../controllers/authController");
const router = express.Router();

// Corrected route path
router.route("/register-user").post(registerUser);
router.route("/login-user").post(loginUser);
router.route("/forgot-password").post(forgotPassword);
router.route("/reset-password").post(resetPassword);

module.exports = router;
