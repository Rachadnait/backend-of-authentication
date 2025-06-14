const router = require("express").Router();
const {
  sendResetPasswordLinkCtrl,
  getResetPasswordLinkCtrl,
  resetPasswordCtrl,
  verifyOtpCtrl,
} = require("../controllers/passwordController");

// /api/password/reset-password-link
router.post("/reset-password-link", sendResetPasswordLinkCtrl);

// verify OTP to reset password
// /api/password/VerifyOTP
router.get("/verifyOTP", verifyOtpCtrl);

// /api/password/reset-password/:userId/:token
// router
//   .route("/reset-password/:userId/:token")
//   .get(getResetPasswordLinkCtrl)
//   .post(resetPasswordCtrl);

module.exports = router;
