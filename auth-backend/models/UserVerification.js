const mongoose = require('mongoose');

const UserVerificationSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    otp: {
        type: String,
        required: true
    },
    expiresAt: {
        type: Date,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 600 // Document will be removed after 10 minutes
    }
});

const UserVerification = mongoose.model('UserVerification', UserVerificationSchema);

module.exports = UserVerification;