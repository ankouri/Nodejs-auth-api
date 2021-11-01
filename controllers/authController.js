const passport = require("passport");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const { google } = require("googleapis");

const OAuth2 = google.auth.OAuth2;

const jwt = require("jsonwebtoken");
const User = require("../models/User");

exports.handleRegister = (req, res) => {
  const { username, email, password, verfiyPassowrd } = req.body;
  let errors = [];

  //CHECK PROVIDED FIELDS VALUES
  if (!username || !email || !password || !verfiyPassowrd) {
    errors.push({ msg: "All fields are required*" });
  }

  //CHECKING PASSWORDS
  if (!password || !verfiyPassowrd) {
    errors.push({ msg: "Passwords do not match*" });
  }

  //CHECKING PASSWORD LENGTH
  if (password.length < 8) {
    errors.push({ msg: "Password must be at least 8 caracters" });
  }

  //IF THERE IS ANY ERRORS
  if (errors.length > 0) {
    res.status(400).json(errors);
  } else {
    User.findOne({ email: email }).then((user) => {
      if (user) {
        //USER INFORMATION ALREADY EXISTS
        errors.push({ msg: "Email ID already registered." });
        res.status(400).json(errors);
      } else {
        const oauth2Client = new OAuth2(
          process.env.OAUTH2CLIENT_ID,
          process.env.OAUTH2CLIENT_SECRET,
          process.env.OAUTH2CLIENT_REDIRECT_URL
        );

        oauth2Client.setCredentials({
          refresh_token: process.env.OAUTH2CLIENT_REFRESH_TOKEN,
        });

        const accessToken = oauth2Client.getAccessToken();
        const token = jwt.sign(
          {
            username,
            email,
            password,
          },
          process.env.SECRET_KEY,
          { expiresIn: "30m" }
        );
        const CLIENTURL = "http://" + req.headers.host;

        //ACTIVATE MESSAGE THAT WILL BE SEND TO CLIENT
        const messageOutput = `
                <h2> Please click on link below to activate your account</h2>
                <p>${CLIENTURL}/auth/activate/${token}</p>
                <p><b>NOTE: </b> The above activation link will expires in 30 minutes.</p>
              `;

        const transporter = nodemailer.createTransport({
          service: "gmail",
          auth: {
            type: "OAUTH2",
            user: "ankouri120@gmail.com",
            clientId:
              "591145269274-8v4o8ttnm66pn3jneq41td2i7kahnk6h.apps.googleusercontent.com",
            clientSecret: "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",
            refreshToken: process.env.OAUTH2CLIENT_REFRESH_TOKEN,
            accessToken: accessToken,
          },
        });

        //MAIL INFORMATION HEADER OPTIONS
        const mailOptions = {
          from: '"Auth Admin" <ankouri120@gmail.com>',
          to: email,
          subject: "Account Verification: NodeJS AUTH",
          generateTextFromHTML: true,
          html: messageOutput,
        };

        //SEND EMAIL USING TRANSPORT ABOVE
        transporter.sendMail(mailOptions, (err, info) => {
          if (err) {
            console.log(err);
            res.status(400).json(err);
          } else {
            console.log("Mail sent: %s", info.response);
            res
              .status(200)
              .json(
                "Activation Link sent to email adress. Please activate to login"
              );
          }
        });
      }
    });
  }
};

exports.handleActivation = (req, res) => {
  //GET TOKEN FROM REQ PARAMS
  const token = req.params.token;
  let errors = [];
  if (token) {
    jwt.verify(token, process.env.SECRET_KEY, (err, decodedToken) => {
      if (err) {
        res
          .status(400)
          .json("Inccorrec or exprired link! Please register again.");
      } else {
        const { username, email, password } = decodedToken;
        User.findOne({ email: email }).then((user) => {
          if (user) {
            res.status(400).json("Email ID already registered! Please login.");
          } else {
            const newUser = new User({
              username,
              email,
              password,
            });

            bcrypt.genSalt(10, (err, salt) => {
              bcrypt.hash(newUser.password, salt, (err, hash) => {
                if (err) res.status(400).json(err);
                newUser.password = hash;
                newUser
                  .save()
                  .then((user) => {
                    res
                      .status(200)
                      .json("Account activated! You can now login");
                  })
                  .catch((err) => {
                    res.status(200).json(`Errors: ${err}`);
                  });
              });
            });
          }
        });
      }
    });
  } else {
    res.status(400).json("Error while activating your account.");
  }
};

exports.handleForgetPassword = (req, res) => {
  const { email } = req.body;

  let errors = [];

  if (!email) {
    res.status(400).json("Please provide an email ID");
  }

  User.findOne({ email: email }).then((user) => {
    if (!user) {
      //USER ALREADY EXISTS
      res.status(400).json("User with email ID does not exist!");
    } else {
      const oauth2Client = new OAuth2(
        process.env.OAUTH2CLIENT_ID,
        process.env.OAUTH2CLIENT_SECRET,
        process.env.OAUTH2CLIENT_REDIRECT_URL
      );

      oauth2Client.setCredentials({
        refresh_token: process.env.OAUTH2CLIENT_REFRESH_TOKEN,
      });

      const accessToken = oauth2Client.getAccessToken();

      const token = jwt.sign(
        {
          _id: user._id,
        },
        process.env.SECRET_KEY,
        {
          expiresIn: "30m",
        }
      );

      const CLIENTURL = "http://" + req.headers.host;
      const messageOutput = `
        <h2>Please click on below link to reset your account password</h2>
                <p>${CLIENTURL}/auth/forgot/${token}</p>
                <p><b>NOTE: </b> The activation link expires in 30 minutes.</p>
        `;

      User.updateOne({ resetLink: token }, (err, success) => {
        if (err) {
          res.status(400).json("Errors resetting password!");
        } else {
          const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
              type: "OAUTH2",
              user: "ankouri120@gmail.com",
              clientId:
                "591145269274-8v4o8ttnm66pn3jneq41td2i7kahnk6h.apps.googleusercontent.com",
              clientSecret: "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",
              refreshToken: process.env.OAUTH2CLIENT_REFRESH_TOKEN,
              accessToken: accessToken,
            },
          });

          //MAIL INFORMATION HEADER OPTIONS
          const mailOptions = {
            from: '"Auth Admin" <ankouri120@gmail.com>',
            to: email,
            subject: "Account Password Reset: NodeJS AUTH",
            generateTextFromHTML: true,
            html: messageOutput,
          };
          //SEND EMAIL USING TRANSPORT ABOVE
          transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
              console.log(err);
              res.status(400).json(err);
            } else {
              console.log("Mail sent: %s", info.response);
              res
                .status(200)
                .json(
                  "Password reset link sent to email ID. Please follow the instructions."
                );
            }
          });
        }
      });
    }
  });
};

exports.handleGotoReset = (req, res) => {
  const { token } = req.params;

  if (token) {
    jwt.verify(token, process.env.SECRET_KEY, (err, decodedToken) => {
      if (err)
        res.status(400).json("Incorrect or expired link! Please try again.");
      else {
        const { _id } = decodedToken;
        User.findById(_id, (err, user) => {
          if (err) {
            res
              .status(400)
              .json("User with email ID does not exist! Please try again.");
          } else {
            res.status(200).json(`/auth/reset/${_id}`);
          }
        });
      }
    });
  } else {
    res.status(400).json("Errors while generating password reset link!");
  }
};

exports.handleResetPassword = (req, res) => {
  let { password, verifyPassword } = req.body;
  const id = req.params.id;

  if (!password || !verifyPassword) {
    res.status(400).json("Please enter all fields.");
  } else if (password.length < 8) {
    res.status(400).json("Please enter all fields.");
  } else if (password !== verifyPassword) {
    res.status(400).json("Passwords do not match.");
  } else {
    bcrypt.genSalt(10, (err, salt) => {
      bcrypt.hash(password, salt, (err, hash) => {
        if (err) res.status(400).json(err);
        password = hash;

        User.findByIdAndUpdate(
          { _id: id },
          { password },
          function (err, result) {
            if (err) {
              res.status(400).json(err);
            } else {
              res.status(200).json("Password reset successfully");
            }
          }
        );
      });
    });
  }
};

exports.handleLogin = (req, res, next) => {
  passport.authenticate("local", function (err, user, info) {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.status(400).json(err);
    }
    req.logIn(user, function (err) {
      if (err) {
        return next(err);
      }
      return res.status(200).json(user);
    });
  })(req, res, next);
};


exports.handleLogout = (req, res) => {
  if( req.isAuthenticated() ) {
    console.log('you have to logout');
    req.logOut();
    return res
    .status(200)
    .json(null);

  } else {
    return res
    .status(403)
    .json("Unauthenticated client is not authorized to use the resource.");
  }

};

exports.ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res
    .status(403)
    .json("Unauthenticated client is not authorized to use the resource.");
};

exports.forwardAuthenthicated = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return next();
  }
  res.status(200).json("User authenticated");
};
