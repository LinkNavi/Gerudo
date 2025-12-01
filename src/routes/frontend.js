const express = require("express");
const router = express.Router();

// Homepage
router.get("/", (req, res) => {
  res.render("index.njk", { title: "Gerudo - Home" });
});

//login page
router.get("/login", (req, res) => {
  res.render("login.njk", { title: "Login" });
});

//register page
router.get("/signup", (req, res) => {
  res.render("signup.njk", { title: "Signup" });
});


// About page
router.get("/about", (req, res) => {
  res.render("about.njk", { title: "About Gerudo" });
});

// Projects page
router.get("/projects", (req, res) => {
  res.render("projects.njk", { title: "Projects" });
});

module.exports = router;
