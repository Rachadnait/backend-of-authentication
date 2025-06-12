const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const {
  User,
  validateRegisterUser,
  validateLoginUser,
} = require("../models/User");
const VerificationToken = require("../models/VerificationToken");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");

/**-----------------------------------------------
 * @desc    Register New User
 * @route   /api/auth/register
 * @method  POST
 * @access  public
 ------------------------------------------------*/
module.exports.registerUserCtrl = asyncHandler(async (req, res) => {
  // validation
  const { error } = validateRegisterUser(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  // Check if user already exists
  let user = await User.findOne({ email: req.body.email });
  if (user) {
    return res.status(400).json({ message: "user already exist" });
  }

  // hashing the password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  // Creating new User & save it toDB
  user = new User({
    username: req.body.username,
    lastname: req.body.lastname,
    phonenumber: req.body.phonenumber,
    email: req.body.email,
    password: hashedPassword,
  });
  await user.save();

  // Creating new VerificationToken & save it toDB
  const verifictionToken = new VerificationToken({
    userId: user._id,
    token: crypto.randomBytes(32).toString("hex"),
  });
  await verifictionToken.save();


  // Making the link
  const link = `${process.env.CLIENT_DOMAIN}/users/${user._id}/verify/${verifictionToken.token}`;

  // Putting the link into an html template
  const htmlTemplate = `
    <div style="font-family: Arial, sans-serif; color: #333;">
      <p>Click on the link below to verify your email</p>
      <a href="${link}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: #fff; text-decoration: none; border-radius: 5px; font-weight: bold;">
        Verify
      </a>
    </div>`;

  // Sending email to the user
  await sendEmail(user.email, "Verify Your Email", htmlTemplate);

  // Response to the client
  res.status(201).json({
    message: "We sent to you an email, please verify your email address",
  });
  // res.status(201).json({
  //   message: "User registered successfully, you need to login to continue",
  //   user: {
  //     _id: user._id,
  //     username: user.username,
  //     lastname: user.lastname,
  //     phonenumber: user.phonenumber,
  //     email: user.email,
  //     // password: user.password, // Don't send password in response just for demo purposes
  //   },
  // });
});

/**-----------------------------------------------
 * @desc    Login User
 * @route   /api/auth/login
 * @method  POST
 * @access  public
 ------------------------------------------------*/
module.exports.loginUserCtrl = asyncHandler(async (req, res) => {
  // validation
  const { error } = validateLoginUser(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  // Check if user exists
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return res.status(400).json({ message: "invalid email or password" });
  }
  // Check if password is correct
  const isPasswordMatch = await bcrypt.compare(
    req.body.password,
    user.password
  );
  if (!isPasswordMatch) {
    return res.status(400).json({ message: "invalid email or password" });
  }

  // Check if user is verified
  if (!user.isAccountVerified) {
    let verificationToken = await VerificationToken.findOne({
      userId: user._id,
    });

    if (!verificationToken) {
      verificationToken = new VerificationToken({
        userId: user._id,
        token: crypto.randomBytes(32).toString("hex"),
      });
      await verificationToken.save();
    }

    const link = `${process.env.CLIENT_DOMAIN}/users/${user._id}/verify/${verificationToken.token}`;

    const htmlTemplate = `
    <div>
      <p>Click on the link below to verify your email</p>
      <a href="${link}">Verify</a>
    </div>`;

    await sendEmail(user.email, "Verify Your Email", htmlTemplate);

    return res.status(400).json({
      message: "We sent to you an email, please verify your email address",
    });

    // return res.status(400).json({
    //   message: "You are login now,",
    //   user: {
    //     _id: user._id,
    //     username: user.username,
    //     lastname: user.lastname,
    //     phonenumber: user.phonenumber,
    //     email: user.email,
    //   },
    // });


  }

  // Generate Auth Token

  const token = user.generateAuthToken();

  res.status(200).json({
    message: "You are login now",
    user: {
      _id: user._id,
      username: user.username,
      lastname: user.lastname,
      phonenumber: user.phonenumber,
      email: user.email,
    },
    token: token
  });
});

/**-----------------------------------------------
 * @desc    Verify User Account
 * @route   /api/auth/:userId/verify/:token
 * @method  GET
 * @access  public
 ------------------------------------------------*/
module.exports.verifyUserAccountCtrl = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.userId);
  if (!user) {
    return res.status(400).json({ message: "invalid link" });
  }

  const verificationToken = await VerificationToken.findOne({
    userId: user._id,
    token: req.params.token,
  });

  if (!verificationToken) {
    return res.status(400).json({ message: "invalid link" });
  }

  user.isAccountVerified = true;
  await user.save();

  await verificationToken.remove();

  res.status(200).json({ message: "Your account verified" });
});
