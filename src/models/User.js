const db = require("../db");

const Site = {
  create: ({ ownerId, slug, title }) => {
    const stmt = db.prepare(`
      INSERT INTO sites (ownerId, slug, title)
      VALUES (?, ?, ?)
    `);
    const info = stmt.run(ownerId, slug, title);
    return { 
      id: info.lastInsertRowid, 
      ownerId, 
      slug, 
      title,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
  },

  findByOwner: (ownerId) => {
    return db.prepare("SELECT * FROM sites WHERE ownerId = ? ORDER BY createdAt DESC")
      .all(ownerId);
  },

  findById: (id) => {
    return db.prepare("SELECT * FROM sites WHERE id = ?").get(id);
  },

  findBySlug: (slug) => {
    return db.prepare("SELECT * FROM sites WHERE slug = ?").get(slug);
  },

  update: ({ id, slug, title }) => {
    const stmt = db.prepare(`
      UPDATE sites 
      SET slug = ?, title = ?, updatedAt = CURRENT_TIMESTAMP 
      WHERE id = ?
    `);
    stmt.run(slug, title, id);
    return Site.findById(id);
  },

  delete: (id) => {
    const stmt = db.prepare("DELETE FROM sites WHERE id = ?");
    stmt.run(id);
  },

  // Get all public sites (for homepage or browse page)
  findAllPublic: (limit = 20) => {
    return db.prepare(`
      SELECT s.*, u.username as ownerUsername 
      FROM sites s
      JOIN users u ON s.ownerId = u.id
      ORDER BY s.createdAt DESC
      LIMIT ?
    `).all(limit);
  },

  // Count sites by owner
  countByOwner: (ownerId) => {
    const result = db.prepare("SELECT COUNT(*) as count FROM sites WHERE ownerId = ?")
      .get(ownerId);
    return result.count;
  }
};

module.exports = Si