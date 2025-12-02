const express = require("express");
const router = express.Router();
const Site = require("../models/Site");

// Homepage
router.get("/", (req, res) => {
  res.render("index.njk", { title: "Gerudo - Home" });
});

// Login page
router.get("/login", (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.render("login.njk", { title: "Login" });
});

// Register page
router.get("/signup", (req, res) => {
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

// View individual site - NEW FORMAT: /~username/sitename
router.get("/~:username/:slug", async (req, res) => {
  try {
    const { username, slug } = req.params;
    const site = await Site.findByUsernameAndSlug(username, slug);
    
    if (!site) {
      return res.status(404).render("404.njk", {
        title: "Site Not Found",
        message: `No site found at /~${username}/${slug}`
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

// Serve individual files from a site - NEW: /~username/sitename/path/to/file.ext
router.get("/~:username/:slug/*", async (req, res) => {
  try {
    const { username, slug } = req.params;
    const filePath = req.params[0]; // Everything after /~username/slug/
    
    const site = await Site.findByUsernameAndSlug(username, slug);
    if (!site) {
      return res.status(404).send('Site not found');
    }
    
    const file = await Site.getFile(site.id, filePath);
    if (!file || !file.content) {
      return res.status(404).send('File not found');
    }
    
    // Set appropriate content type
    res.type(file.mime_type || 'text/plain');
    res.send(file.content);
    
  } catch (err) {
    console.error('Serve file error:', err);
    res.status(500).send('Error loading file');
  }
});

module.exports = router;
