const mongoose = require('mongoose');

const UserOtpVerificationSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    otp: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 600 // OTP expires after 10 minutes
    }
});
const UserOtpVerification = mongoose.model('UserOtpVerification', UserOtpVerificationSchema);

module.exports = UserOtpVerification;