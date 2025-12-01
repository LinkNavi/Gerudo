const express = require("express");
const router = express.Router();
const Site = require("../models/Site");
const User = require("../models/User");
const requireAuth = require("../middleware/auth");

// ============================================================
// VALIDATION HELPERS
// ============================================================

function validateSlug(slug) {
  if (!slug || typeof slug !== 'string') {
    return { valid: false, error: 'Slug is required' };
  }
  
  if (slug.length < 3) {
    return { valid: false, error: 'Slug must be at least 3 characters' };
  }
  
  if (slug.length > 50) {
    return { valid: false, error: 'Slug must be less than 50 characters' };
  }
  
  // Only allow lowercase letters, numbers, and hyphens
  if (!/^[a-z0-9-]+$/.test(slug)) {
    return { 
      valid: false, 
      error: 'Slug can only contain lowercase letters, numbers, and hyphens' 
    };
  }
  
  // Can't start or end with hyphen
  if (slug.startsWith('-') || slug.endsWith('-')) {
    return { 
      valid: false, 
      error: 'Slug cannot start or end with a hyphen' 
    };
  }
  
  return { valid: true };
}

function validateTitle(title) {
  if (!title || typeof title !== 'string') {
    return { valid: false, error: 'Title is required' };
  }
  
  if (title.trim().length < 1) {
    return { valid: false, error: 'Title cannot be empty' };
  }
  
  if (title.length > 100) {
    return { valid: false, error: 'Title must be less than 100 characters' };
  }
  
  return { valid: true };
}

// ============================================================
// DASHBOARD HOME
// ============================================================

router.get("/", requireAuth, (req, res) => {
  try {
    const sites = User.listSites(req.session.userId);
    
    res.render("dashboard.njk", { 
      sites: sites,
      totalSites: sites.length,
      title: "Dashboard"
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    req.flash('error', 'Failed to load dashboard');
    res.redirect('/');
  }
});

// ============================================================
// CREATE SITE
// ============================================================

router.post("/create-site", requireAuth, async (req, res) => {
  try {
    const { slug, title } = req.body;
    
    // Validate slug
    const slugValidation = validateSlug(slug);
    if (!slugValidation.valid) {
      return res.status(400).json({ 
        error: slugValidation.error 
      });
    }
    
    // Validate title
    const titleValidation = validateTitle(title);
    if (!titleValidation.valid) {
      return res.status(400).json({ 
        error: titleValidation.error 
      });
    }
    
    // Create site
    const site = Site.create({
      ownerId: req.session.userId,
      slug: slug.toLowerCase().trim(),
      title: title.trim()
    });
    
    req.flash('success', `Site "${title}" created successfully!`);
    
    res.json({ 
      success: true,
      site: site
    });
    
  } catch (err) {
    console.error('Create site error:', err);
    
    // Check if it's a duplicate slug error
    if (err.message && err.message.includes('UNIQUE constraint')) {
      return res.status(400).json({ 
        error: 'A site with this slug already exists' 
      });
    }
    
    res.status(500).json({ 
      error: 'Failed to create site' 
    });
  }
});

// ============================================================
// UPDATE SITE
// ============================================================

router.post("/update-site/:id", requireAuth, async (req, res) => {
  try {
    const siteId = parseInt(req.params.id, 10);
    const { slug, title } = req.body;
    
    // Validate site exists and user owns it
    const site = Site.findById(siteId);
    if (!site) {
      return res.status(404).json({ 
        error: 'Site not found' 
      });
    }
    
    if (site.ownerId !== req.session.userId) {
      return res.status(403).json({ 
        error: 'You do not have permission to edit this site' 
      });
    }
    
    // Validate slug
    const slugValidation = validateSlug(slug);
    if (!slugValidation.valid) {
      return res.status(400).json({ 
        error: slugValidation.error 
      });
    }
    
    // Validate title
    const titleValidation = validateTitle(title);
    if (!titleValidation.valid) {
      return res.status(400).json({ 
        error: titleValidation.error 
      });
    }
    
    // Update site
    const updatedSite = Site.update({
      id: siteId,
      slug: slug.toLowerCase().trim(),
      title: title.trim()
    });
    
    req.flash('success', 'Site updated successfully!');
    
    res.json({ 
      success: true,
      site: updatedSite
    });
    
  } catch (err) {
    console.error('Update site error:', err);
    
    if (err.message && err.message.includes('UNIQUE constraint')) {
      return res.status(400).json({ 
        error: 'A site with this slug already exists' 
      });
    }
    
    res.status(500).json({ 
      error: 'Failed to update site' 
    });
  }
});

// ============================================================
// DELETE SITE
// ============================================================

router.post("/delete-site/:id", requireAuth, async (req, res) => {
  try {
    const siteId = parseInt(req.params.id, 10);
    
    // Validate site exists and user owns it
    const site = Site.findById(siteId);
    if (!site) {
      return res.status(404).json({ 
        error: 'Site not found' 
      });
    }
    
    if (site.ownerId !== req.session.userId) {
      return res.status(403).json({ 
        error: 'You do not have permission to delete this site' 
      });
    }
    
    // Delete site
    Site.delete(siteId);
    
    req.flash('success', `Site "${site.title}" deleted successfully`);
    
    res.json({ 
      success: true 
    });
    
  } catch (err) {
    console.error('Delete site error:', err);
    res.status(500).json({ 
      error: 'Failed to delete site' 
    });
  }
});

// ============================================================
// VIEW SITE (Public view)
// ============================================================

router.get("/site/:slug", (req, res) => {
  try {
    const slug = req.params.slug;
    const site = Site.findBySlug(slug);
    
    if (!site) {
      return res.status(404).render("404.njk", {
        title: "Site Not Found",
        message: `No site found with slug "${slug}"`
      });
    }
    
    res.render("site-view.njk", {
      site: site,
      title: site.title
    });
    
  } catch (err) {
    console.error('View site error:', err);
    res.status(500).render("error.njk", {
      title: "Error",
      message: "Failed to load site"
    });
  }
});

module.exports = router;