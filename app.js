const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const cookieParser = require("cookie-parser");
var jwt = require("jsonwebtoken");

const app = express();
app.use(cookieParser());

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.set("strictQuery", false);
mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
});

const User = mongoose.model("User", userSchema);

// routes begin //

app.get("/", (req, res) => {
  res.render("home");
});

// =========================================

app
  .route("/login")
  .get(
    ("/login",
    (req, res) => {
      if (req.cookies.jwtToken) {
        var decoded = jwt.verify(req.cookies.jwtToken, "jazz");
        User.findOne({ username: decoded.username }, (err, found) => {
          if (found) {
            res.render("secrets");
          } else {
            res.redirect("/");
          }
        });
      } else {
        res.render("login");
      }
    })
  )
  .post(
    ("/login",
    (req, res) => {
      const user = {
        username: req.body.username,
        password: req.body.password,
      };
      User.findOne({ username: req.body.username }, (err, found) => {
        if (!err) {
          if (found) {
            bcrypt.compare(
              req.body.password,
              found.password,
              function (err, result) {
                if (result === true) {
                  var token = jwt.sign(
                    { username: req.body.username, password: found.password },
                    "jazz"
                  );
                  res.cookie("jwtToken", token, {
                    httpOnly: true,
                  });
                  res.render("secrets");
                } else {
                  res.send("Sorry, wrong password");
                }
              }
            );
          } else {
            res.send(
              "Sorry, this username doesn't exist with us. Please register it."
            );
          }
        }
      });
    })
  );

// =========================================

app
  .route("/register")
  .get(
    ("/register",
    (req, res) => {
      if (req.cookies.jwtToken) {
        var decoded = jwt.verify(req.cookies.jwtToken, "jazz");
        User.findOne({ username: decoded.username }, (err, found) => {
          if (found) {
            res.render("secrets");
          } else {
            console.log("User do not exist");
            res.redirect("/");
          }
        });
      } else {
        res.render("register");
      }
    })
  )
  .post(
    ("/register",
    (req, res) => {
      bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        const newUser = new User({
          username: req.body.username,
          password: hash,
        });
        newUser.save((err) => {
          if (err) {
            res.redirect("/register");
          } else {
            res.redirect("/login");
          }
        });
      });
    })
  );

// =========================================

app.get("/secrets", (req, res) => {
  if (req.cookies.jwtToken) {
    var decoded = jwt.verify(req.cookies.jwtToken, "jazz");
    User.findOne({ username: decoded.username }, (err, found) => {
      if (found) {
        res.redirect("/secrets");
      } else {
        res.redirect("/");
      }
    });
  } else {
    res.render("login");
  }
});

// =========================================

app.get("/logout", function (req, res) {
  res.clearCookie("jwtToken");
  res.redirect("/");
});

// =========================================

app.listen("3000", (req, res) => {
  console.log("Server started on port 3000");
});
