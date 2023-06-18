const nodemailer = require('nodemailer');

const sendEmail = async options => {
  // Create a transporter
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD
    }
    //   Activate less secure app in gmail
  });

  // Define the email options
  const mailOptions = {
    from: 'Jonas Smith <Jonas@jonas.io',
    to: options.email,
    subject: options.subject,
    text: options.message
    // Html
  };

  // Actullly send the email
  await transporter.sendMail(mailOptions);
};

module.exports = sendEmail;
