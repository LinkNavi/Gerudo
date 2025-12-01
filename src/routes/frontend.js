const express = require("express");
const router = express.Router();
const Site = require("../models/Site");

// Homepage
router.get("/", (req, res) => {
  res.render("index.njk", { title: "Gerudo - Home" });
});

// Login page
router.get("/login", (req, res) => {
  // Redirect if already logged in
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.render("login.njk", { title: "Login" });
});

// Register page
router.get("/signup", (req, res) => {
  // Redirect if already logged in
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.render("signup.njk", { title: "Sign Up" });
});

// About page
router.get("/about", (req, res) => {
  res.render("about.njk", { title: "About Gerudo" });
});

// Browse sites page
router.get("/browse", async (req, res) => {
  try {
    const sites = await Site.findAllPublic(50);
    res.render("browse.njk", { 
      title: "Browse Sites",
      sites: sites
    });
  } catch (err) {
    console.error('Browse error:', err);
    res.render("browse.njk", { 
      title: "Browse Sites",
      sites: [],
      error: "Failed to load sites"
    });
  }
});

// View individual site
router.get("/~:slug", async (req, res) => {
  try {
    const slug = req.params.slug;
    const site = await Site.findBySlug(slug);
    
    if (!site) {
      return res.status(404).render("404.njk", {
        title: "Site Not Found",
        message: `No site found with slug "${slug}"`
      });
    }
    
    // Get the index.html file or show a default page
    const indexFile = await Site.getFile(site.id, 'index.html');
    
    if (indexFile && indexFile.content) {
      // Serve the HTML content directly
      res.type('html');
      res.send(indexFile.content);
    } else {
      // Show a default "under construction" page
      res.render("site-default.njk", {
        site: site,
        title: site.title
      });
    }
    
  } catch (err) {
    console.error('View site error:', err);
    res.status(500).render("error.njk", {
      title: "Error",
      message: "Failed to load site"
    });
  }
});

module.exports = router;
