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

function getMimeType(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  const mimeTypes = {
    'html': 'text/html',
    'htm': 'text/html',
    'css': 'text/css',
    'js': 'application/javascript',
    'json': 'application/json',
    'txt': 'text/plain',
    'md': 'text/markdown',
    'svg': 'image/svg+xml',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'webp': 'image/webp',
    'ico': 'image/x-icon',
    'woff': 'font/woff',
    'woff2': 'font/woff2',
    'ttf': 'font/ttf',
    'otf': 'font/otf',
  };
  return mimeTypes[ext] || 'application/octet-stream';
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
// VIEW SITE (with file management)
// ============================================================
router.get("/site/:slug", requireAuth, async (req, res) => {
  try {
    const slug = req.params.slug;
    
    // Find site by owner and slug
    const sites = await Site.findByOwner(req.session.userId);
    const site = sites.find(s => s.slug === slug);
    
    if (!site) {
      req.flash('error', 'Site not found');
      return res.redirect('/dashboard');
    }
    
    const files = await Site.listFiles(site.id);
    const indexFile = files.find(f => f.path === 'index.html');
    const totalSize = await Site.getSiteTotalSize(site.id);
    
    res.render("site-view.njk", {
      site: site,
      files: files,
      indexFile: indexFile,
      totalSize: totalSize,
      title: site.title
    });
    
  } catch (err) {
    console.error('View site error:', err);
    req.flash('error', 'Failed to load site');
    res.redirect('/dashboard');
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
    
    if (err.code === '23505') {
      req.flash('error', 'You already have a site with this slug');
    } else {
      req.flash('error', 'Failed to create site');
    }
    
    res.redirect('/dashboard');
  }
});

// ============================================================
// UPLOAD FILE (Text Content)
// ============================================================
router.post("/upload-file/:siteId", requireAuth, async (req, res) => {
  try {
    const siteId = parseInt(req.params.siteId, 10);
    const { path, content, mimeType } = req.body;
    
    const site = await Site.findById(siteId);
    if (!site) {
      req.flash('error', 'Site not found');
      return res.redirect('/dashboard');
    }
    
    if (site.owner_id !== req.session.userId) {
      req.flash('error', 'You do not have permission to upload files to this site');
      return res.redirect('/dashboard');
    }
    
    if (!path || typeof path !== 'string' || path.trim().length === 0) {
      req.flash('error', 'File path is required');
      return res.redirect(`/dashboard/site/${site.slug}`);
    }
    
    if (!/^[a-zA-Z0-9._/-]+$/.test(path)) {
      req.flash('error', 'Invalid file path');
      return res.redirect(`/dashboard/site/${site.slug}`);
    }
    
    if (!content || typeof content !== 'string' || content.trim().length === 0) {
      req.flash('error', 'File content is required');
      return res.redirect(`/dashboard/site/${site.slug}`);
    }
    
    // Check total site size (10MB limit per site)
    const currentSize = await Site.getSiteTotalSize(siteId);
    if (currentSize + content.length > 10 * 1024 * 1024) {
      req.flash('error', 'Site storage limit exceeded (10MB max)');
      return res.redirect(`/dashboard/site/${site.slug}`);
    }
    
    await Site.saveFile({
      siteId: siteId,
      path: path.trim(),
      content: content,
      mimeType: mimeType || 'text/plain',
      size: content.length
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
// UPLOAD BINARY FILE (API endpoint for drag-and-drop)
// ============================================================
router.post("/upload-binary/:siteId", requireAuth, async (req, res) => {
  try {
    const siteId = parseInt(req.params.siteId, 10);
    
    const site = await Site.findById(siteId);
    if (!site) {
      return res.status(404).json({ error: 'Site not found' });
    }
    
    if (site.owner_id !== req.session.userId) {
      return res.status(403).json({ error: 'Permission denied' });
    }
    
    // Get raw body as buffer
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', async () => {
      try {
        const buffer = Buffer.concat(chunks);
        const filename = req.headers['x-filename'] || 'unnamed.txt';
        const mimeType = req.headers['content-type'] || getMimeType(filename);
        
        // Validate filename
        if (!/^[a-zA-Z0-9._/-]+$/.test(filename)) {
          return res.status(400).json({ error: 'Invalid filename' });
        }
        
        // Check size (5MB per file)
        if (buffer.length > 5 * 1024 * 1024) {
          return res.status(400).json({ error: 'File too large (5MB max)' });
        }
        
        // Check total site size
        const currentSize = await Site.getSiteTotalSize(siteId);
        if (currentSize + buffer.length > 10 * 1024 * 1024) {
          return res.status(400).json({ error: 'Site storage limit exceeded (10MB max)' });
        }
        
        // Convert binary to base64 for text storage
        const content = buffer.toString('base64');
        
        await Site.saveFile({
          siteId: siteId,
          path: filename,
          content: content,
          mimeType: mimeType,
          size: buffer.length
        });
        
        res.json({ 
          success: true, 
          filename: filename,
          size: buffer.length,
          message: `File "${filename}" uploaded successfully!`
        });
        
      } catch (err) {
        console.error('Binary upload error:', err);
        res.status(500).json({ error: 'Failed to upload file' });
      }
    });
    
  } catch (err) {
    console.error('Upload binary error:', err);
    res.status(500).json({ error: 'Failed to upload file' });
  }
});

// ============================================================
// DELETE FILE
// ============================================================
router.post("/delete-file/:siteId/:fileId", requireAuth, async (req, res) => {
  try {
    const siteId = parseInt(req.params.siteId, 10);
    const fileId = parseInt(req.params.fileId, 10);
    
    const site = await Site.findById(siteId);
    if (!site) {
      req.flash('error', 'Site not found');
      return res.redirect('/dashboard');
    }
    
    if (site.owner_id !== req.session.userId) {
      req.flash('error', 'You do not have permission to delete files from this site');
      return res.redirect('/dashboard');
    }
    
    const files = await Site.listFiles(siteId);
    const file = files.find(f => f.id === fileId);
    
    if (!file) {
      req.flash('error', 'File not found');
      return res.redirect(`/dashboard/site/${site.slug}`);
    }
    
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
      req.flash('error', 'You already have a site with this slug');
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

module.exports = router;
