const express = require('express');
const router = express.Router();
// TODO: Require user model
const User = require('../models/User.model.js');
const passport = require('passport');

// TODO: Add bcrypt to encrypt passwords
const bcrypt = require('bcrypt');
const bcryptSalt = 10;

// SIGN UP
router.get('/signup', (req, res, next) => {
  res.render('auth/signup');
});
 
router.post('/signup', (req, res, next) => {
  const { username, password } = req.body;
 
  // 1. Check username and password are not empty
  if (!username || !password) {
    res.render('auth/signup', { errorMessage: 'Indicate username and password' });
    return;
  }
 
  User.findOne({ username })
    .then((user) => {
      // 2. Check user does not already exist
      if (user !== null) {
        res.render('auth/signup', { message: 'The username already exists' });
        return;
      }
 
      // Encrypt the password
      const salt = bcrypt.genSaltSync(bcryptSalt);
      const hashPass = bcrypt.hashSync(password, salt);
 
      //
      // Save the user in DB
      //
 
      const newUser = new User({
        username,
        password: hashPass,
      });
 
      newUser
        .save()
        .then(() => res.redirect('/'))
        .catch((err) => next(err));
    })
    .catch((err) => next(err));
});

// LOG IN
router.get("/login", (req, res, next) => {
  res.render("auth/login", { "errorMessage": req.flash("error") });                  
});
 
router.post("/login", passport.authenticate("local", {
  successRedirect: "/private-page",
  failureRedirect: "/login",
  failureFlash: true // 
}));

// LOG OUT 
router.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/login');
});


// PRIVATE PAGE 
router.get("/private-page", (req, res) => {
  if (!req.user) {
    res.redirect('/login');
    return;
  }

  res.render("auth/private", { user: req.user });
});

module.exports = router;
