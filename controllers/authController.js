const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');
const sendEmail = require('../utils/email');

const signToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

exports.signUp = catchAsync(async (req, res) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
    passwordChangedAt: req.body.passwordChangedAt,
    role: req.body.role
  });

  //  Log the new user in as soon as he signUp
  const token = signToken(newUser._id);

  res.status(201).json({
    status: 'success',
    data: {
      token,
      user: newUser
    }
  });
});

exports.logIn = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // Check user & password is ivalid
  if (!email || !password)
    return next(new AppError('Please provide email and password', 400));

  // user & password is valid
  const user = await User.findOne({ email }).select('+password');

  if (!user || !(await user.correctPassword(password, user.password))) {
    // Un Authorized
    return next(new AppError('Incorrect email or password', 401));
  }

  const token = signToken(user._id);

  // Send response
  res.status(200).json({
    status: 'success',
    token
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  // 1) Getting token and check if it's there
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return next(
      new AppError('You are not logged in! Please log in to get access.', 401)
    );
  }

  //2)  Verify token
  const decode = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  //3) Check if user still exists
  const currentUser = await User.findById(decode.id);

  if (!currentUser) {
    return next(
      new AppError('The user belonging to the token does not exist', 401)
    );
  }

  // Check if user changed password and token was issued
  if (currentUser.changedPasswordAfter(decode.iat)) {
    return next(
      new AppError('User recently changed password! Please try again.', 401)
    );
  }

  // Grand Acces to protected route
  req.user = currentUser;
  next();
});

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403)
      );
    }

    next();
  };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // Get user based on posted email
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return next(new AppError('There is no user with the provided email', 404));
  }

  // generate random token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // Send it to user email
  const reqURL = `${req.protocol}://${req.get(
    'host'
  )}/api/v1/users/resetPassword/${resetToken}`;

  const message = `Forgot your password submit a patch request with your new password and passwordConfirm to : ${reqURL}.\nIf you don't forgot your password please ignore this email!`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'Your password reset token (valid for 10 min)',
      message
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    console.log(err);

    return next(
      new AppError('Thre was a error sending the email, try again later!', 500)
    );
  }

  res.status(200).json({
    status: 'success',
    message: 'Token sent to email!'
  });
});

exports.resetPassword = (req, res, next) => {};
