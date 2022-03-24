require("dotenv").config();
const express = require("express");
const app = express();
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;

const findOrCreate = require("mongoose-findorcreate");

app.set("view engine", "ejs");
app.use(
  express.urlencoded({
    extended: true,
  })
);

app.use(express.static(__dirname + "/public"));

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect("mongodb://localhost:27017/userDB");

  const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleID: String,
    facebookID: String,
    secrets: []
  });

  userSchema.plugin(passportLocalMongoose);
  userSchema.plugin(findOrCreate);

  const User = mongoose.model("user", userSchema);

  passport.use(User.createStrategy());

  passport.serializeUser(function (user, done) {
    done(null, user);
  });

  passport.deserializeUser(function (user, done) {
    done(null, user);
  });

  const secretSchema = new mongoose.Schema({
    secret: String,
  });

  const Secret = mongoose.model("secret", secretSchema);

  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:2000/auth/google/secrets",
      },
      function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleID: profile.id }, function (err, user) {
          return cb(err, user);
        });
      }
    )
  );

  passport.use(
    new FacebookStrategy(
      {
        clientID: process.env.CLIENT_F_ID,
        clientSecret: process.env.CLIENT_F_SECRET,
        callbackURL: "http://localhost:2000/auth/facebook/secrets",
      },
      function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ facebookID: profile.id }, function (err, user) {
          return cb(err, user);
        });
      }
    )
  );

  app.get("/", function (req, res) {
    res.render("home");
  });

  app.get("/login", function (req, res) {
    if (req.isAuthenticated()) {
      res.render("secrets");
    } else {
      res.render("login");
    }
  });

  app.get("/register", function (req, res) {
    if (req.isAuthenticated()) {
      res.render("secrets");
    } else {
      res.render("register");
    }
  });

  app.get("/secrets", function (req, res) {
    if (req.isAuthenticated()) {
      Secret.find({}, function (err, secrets) {
        const randomSecret =
          secrets[Math.floor(Math.random() * secrets.length)].secret;
        res.render("secrets", { randomSecret });
      });
    } else {
      res.redirect("/login");
    }
  });

  app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
      res.render("submit");
    } else {
      res.redirect("/login");
    }
  });

  app.get("/logout", function (req, res) {
    req.logout();
    res.redirect("/");
  });

  app.get(
    "/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
  );

  app.get(
    "/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function (req, res) {
      // Successful authentication, redirect home.
      res.redirect("/secrets");
    }
  );

  app.get("/auth/facebook", passport.authenticate("facebook"));

  app.get(
    "/auth/facebook/secrets",
    passport.authenticate("facebook", { failureRedirect: "/login" }),
    function (req, res) {
      // Successful authentication, redirect home.
      res.redirect("/secrets");
    }
  );

  app.post("/register", function (req, res) {
    User.register(
      { username: req.body.username, active: false },
      req.body.password,
      function (err, user) {
        if (err) {
          console.log("Email already exist!");
          res.redirect("/register");
        } else {
          passport.authenticate("local")(req, res, function () {
            res.redirect("/secrets");
          });
        }
      }
    );
  });

  app.post(
    "/login",
    passport.authenticate("local", { failureRedirect: "/login" }),
    function (req, res) {
      res.redirect("secrets");
    }
  );

  app.post("/submit", function (req, res) {
    const newSecret = new Secret({
      secret: req.body.secret,
    });
    newSecret.save();

    User.findOneAndUpdate({_id:req.user._id},{"$push": {secrets: (req.body.secret)}}, function (err){
      if(!err){
        res.redirect("/secrets");
      }
    })
  });

  app.listen(2000, function () {
    console.log("Server started successfully");
  });
}
