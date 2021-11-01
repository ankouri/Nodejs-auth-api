const express = require("express");
const mongoose = require("mongoose");
require("dotenv").config();
const session = require("express-session");
const passport = require("passport");
const authController = require("./controllers/authController");
const app = express();
app.use(express.json()); 

//PASSPORT CONFIG
require("./config/passport")(passport);


//CONNECT TO MONGODB
try {

  mongoose.connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex:true,
  });

} catch (err) {

    console.log('Error Connecting to MongoDB');

}

//CONFIG EXPRESS SESSION
app.use( session({
    secret: process.env.SESSIONKEY,
    resave: true,
    saveUninitialized: true
}) );

//PASSPORT MIDDLEWARES
app.use(passport.initialize());
app.use(passport.session());


//ROUTES
app.use('/api/auth', require('./routes/authRouter'));

app.get('/api/dashboard', authController.ensureAuthenticated, (req, res) => {
    res.send(req.user.email);
})
//SERVER LISTING PORT
app.listen(process.env.PORT, () => {
  console.log(`Server listening in port ${process.env.PORT}`);
});
