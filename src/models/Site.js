const db = require("../db");

const Site = {
  create: ({ ownerId, slug, title }) => {
    const stmt = db.prepare(`
      INSERT INTO sites (ownerId, slug, title)
      VALUES (?, ?, ?)
    `);
    const info = stmt.run(ownerId, slug, title);
    return { id: info.lastInsertRowid, ownerId, slug, title };
  },

  findByOwner: (ownerId) => {
    return db.prepare("SELECT * FROM sites WHERE ownerId = ?").all(ownerId);
  },

  findById: (id) => {
    return db.prepare("SELECT * FROM sites WHERE id = ?").get(id);
  },

  update: ({ id, slug, title }) => {
    const stmt = db.prepare(`
      UPDATE sites SET slug = ?, title = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?
    `);
    stmt.run(slug, title, id);
    return Site.findById(id);
  },

  delete: (id) => {
    const stmt = db.prepare("DELETE FROM sites WHERE id = ?");
    stmt.run(id);
  }
};

module.exports = Site;
