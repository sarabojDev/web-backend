const express = require("express");
const { registerUser, loginUser, forgotPassword, resetPassword, refreshLoginUser } = require("../controllers/authController");
const router = express.Router();

// Corrected route path
router.route("/register-user").post(registerUser);
router.route("/login-user").post(loginUser);
router.route("/forgot-password").post(forgotPassword);
router.route("/reset-password").post(resetPassword);
router.route("/refresh-login").get(refreshLoginUser);

module.exports = router;
