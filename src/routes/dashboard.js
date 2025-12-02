const express = require("express");
const router = express.Router();
const Site = require("../models/Site");
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
  
  if (!/^[a-z0-9-]+$/.test(slug)) {
    return { 
      valid: false, 
      error: 'Slug can only contain lowercase letters, numbers, and hyphens' 
    };
  }
  
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
router.get("/", requireAuth, async (req, res) => {
  try {
    const sites = await Site.findByOwner(req.session.userId);
    
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
    
    const slugValidation = validateSlug(slug);
    if (!slugValidation.valid) {
      req.flash('error', slugValidation.error);
      return res.redirect('/dashboard');
    }
    
    const titleValidation = validateTitle(title);
    if (!titleValidation.valid) {
      req.flash('error', titleValidation.error);
      return res.redirect('/dashboard');
    }
    
    await Site.create({
      ownerId: req.session.userId,
      slug: slug.toLowerCase().trim(),
      title: title.trim()
    });
    
    req.flash('success', `Site "${title}" created successfully!`);
    res.redirect('/dashboard');
    
  } catch (err) {
    console.error('Create site error:', err);
    
    if (err.code === '23505') { // PostgreSQL unique violation
      req.flash('error', 'A site with this slug already exists');
    } else {
      req.flash('error', 'Failed to create site');
    }
    
    res.redirect('/dashboard');
  }
});

// ============================================================
// UPLOAD FILE
// ============================================================
router.post("/upload-file/:siteId", requireAuth, async (req, res) => {
  try {
    const siteId = parseInt(req.params.siteId, 10);
    const { path, content, mimeType } = req.body;
    
    // Verify site ownership
    const site = await Site.findById(siteId);
    if (!site) {
      req.flash('error', 'Site not found');
      return res.redirect('/dashboard');
    }
    
    if (site.owner_id !== req.session.userId) {
      req.flash('error', 'You do not have permission to upload files to this site');
      return res.redirect('/dashboard');
    }
    
    // Validate path
    if (!path || typeof path !== 'string') {
      req.flash('error', 'File path is required');
      return res.redirect(`/dashboard/site/${site.slug}`);
    }
    
    if (!/^[a-zA-Z0-9._/-]+$/.test(path)) {
      req.flash('error', 'Invalid file path');
      return res.redirect(`/dashboard/site/${site.slug}`);
    }
    
    // Validate content
    if (!content || typeof content !== 'string') {
      req.flash('error', 'File content is required');
      return res.redirect(`/dashboard/site/${site.slug}`);
    }
    
    // Limit file size (e.g., 1MB)
    if (content.length > 1024 * 1024) {
      req.flash('error', 'File content is too large (max 1MB)');
      return res.redirect(`/dashboard/site/${site.slug}`);
    }
    
    // Save the file
    await Site.saveFile({
      siteId: siteId,
      path: path.trim(),
      content: content,
      mimeType: mimeType || 'text/plain'
    });
    
    req.flash('success', `File "${path}" uploaded successfully!`);
    res.redirect(`/dashboard/site/${site.slug}`);
    
  } catch (err) {
    console.error('Upload file error:', err);
    req.flash('error', 'Failed to upload file');
    res.redirect('/dashboard');
  }
});

// ============================================================
// DELETE FILE
// ============================================================
router.post("/delete-file/:siteId/:fileId", requireAuth, async (req, res) => {
  try {
    const siteId = parseInt(req.params.siteId, 10);
    const fileId = parseInt(req.params.fileId, 10);
    
    // Verify site ownership
    const site = await Site.findById(siteId);
    if (!site) {
      req.flash('error', 'Site not found');
      return res.redirect('/dashboard');
    }
    
    if (site.owner_id !== req.session.userId) {
      req.flash('error', 'You do not have permission to delete files from this site');
      return res.redirect('/dashboard');
    }
    
    // Get file info for the flash message
    const files = await Site.listFiles(siteId);
    const file = files.find(f => f.id === fileId);
    
    if (!file) {
      req.flash('error', 'File not found');
      return res.redirect(`/dashboard/site/${site.slug}`);
    }
    
    // Delete the file
    await Site.deleteFile(siteId, file.path);
    
    req.flash('success', `File "${file.path}" deleted successfully`);
    res.redirect(`/dashboard/site/${site.slug}`);
    
  } catch (err) {
    console.error('Delete file error:', err);
    req.flash('error', 'Failed to delete file');
    res.redirect('/dashboard');
  }
});

// ============================================================
// EDIT SITE PAGE
// ============================================================
router.get("/edit-site/:id", requireAuth, async (req, res) => {
  try {
    const siteId = parseInt(req.params.id, 10);
    const site = await Site.findById(siteId);
    
    if (!site) {
      req.flash('error', 'Site not found');
      return res.redirect('/dashboard');
    }
    
    if (site.owner_id !== req.session.userId) {
      req.flash('error', 'You do not have permission to edit this site');
      return res.redirect('/dashboard');
    }
    
    res.render("edit-site.njk", {
      site: site,
      title: `Edit ${site.title}`
    });
    
  } catch (err) {
    console.error('Edit site page error:', err);
    req.flash('error', 'Failed to load site');
    res.redirect('/dashboard');
  }
});

// ============================================================
// UPDATE SITE
// ============================================================
router.post("/update-site/:id", requireAuth, async (req, res) => {
  try {
    const siteId = parseInt(req.params.id, 10);
    const { slug, title } = req.body;
    
    const site = await Site.findById(siteId);
    if (!site) {
      req.flash('error', 'Site not found');
      return res.redirect('/dashboard');
    }
    
    if (site.owner_id !== req.session.userId) {
      req.flash('error', 'You do not have permission to edit this site');
      return res.redirect('/dashboard');
    }
    
    const slugValidation = validateSlug(slug);
    if (!slugValidation.valid) {
      req.flash('error', slugValidation.error);
      return res.redirect(`/dashboard/edit-site/${siteId}`);
    }
    
    const titleValidation = validateTitle(title);
    if (!titleValidation.valid) {
      req.flash('error', titleValidation.error);
      return res.redirect(`/dashboard/edit-site/${siteId}`);
    }
    
    await Site.update({
      id: siteId,
      slug: slug.toLowerCase().trim(),
      title: title.trim()
    });
    
    req.flash('success', 'Site updated successfully!');
    res.redirect('/dashboard');
    
  } catch (err) {
    console.error('Update site error:', err);
    
    if (err.code === '23505') {
      req.flash('error', 'A site with this slug already exists');
    } else {
      req.flash('error', 'Failed to update site');
    }
    
    res.redirect('/dashboard');
  }
});

// ============================================================
// DELETE SITE
// ============================================================
router.post("/delete-site/:id", requireAuth, async (req, res) => {
  try {
    const siteId = parseInt(req.params.id, 10);
    
    const site = await Site.findById(siteId);
    if (!site) {
      req.flash('error', 'Site not found');
      return res.redirect('/dashboard');
    }
    
    if (site.owner_id !== req.session.userId) {
      req.flash('error', 'You do not have permission to delete this site');
      return res.redirect('/dashboard');
    }
    
    await Site.delete(siteId);
    
    req.flash('success', `Site "${site.title}" deleted successfully`);
    res.redirect('/dashboard');
    
  } catch (err) {
    console.error('Delete site error:', err);
    req.flash('error', 'Failed to delete site');
    res.redirect('/dashboard');
  }
});

// ============================================================
// VIEW SITE (Public view)
// ============================================================
router.get("/site/:slug", async (req, res) => {
  try {
    const slug = req.params.slug;
    const site = await Site.findBySlug(slug);
    
    if (!site) {
      return res.status(404).render("404.njk", {
        title: "Site Not Found",
        message: `No site found with slug "${slug}"`
      });
    }
    
    const files = await Site.listFiles(site.id);
    const indexFile = files.find(f => f.path === 'index.html');
    
    res.render("site-view.njk", {
      site: site,
      files: files,
      indexFile: indexFile,
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
