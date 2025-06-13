const router = require("express").Router();
const { registerUserCtrl, loginUserCtrl, verifyUserAccountCtrl ,verifyOtpUserAccountCtrl } = require("../controllers/authController")

// /api/auth/register
router.post("/register", registerUserCtrl);

// /api/auth/login
router.post("/login", loginUserCtrl);

// verification without OTP
// /api/auth/:userId/verify/:token
router.get("/:userId/verify/:token", verifyUserAccountCtrl);

// verification with OTP
// /api/auth/:userId/:otp/verify/:token
router.get("/:userId/otp/:token/:otp", verifyOtpUserAccountCtrl);

module.exports = router;