// models/Site.js
const { pool } = require("../db");

const Site = {
  async create({ ownerId, slug, title }) {
    const result = await pool.query(
      'INSERT INTO sites (owner_id, slug, title) VALUES ($1, $2, $3) RETURNING *',
      [ownerId, slug, title]
    );
    return result.rows[0];
  },

  async findByOwner(ownerId) {
    const result = await pool.query(
      'SELECT * FROM sites WHERE owner_id = $1 ORDER BY created_at DESC',
      [ownerId]
    );
    return result.rows;
  },

  async findById(id) {
    const result = await pool.query(
      'SELECT * FROM sites WHERE id = $1',
      [id]
    );
    return result.rows[0];
  },

  async findBySlug(slug) {
    const result = await pool.query(
      'SELECT s.*, u.username as owner_username FROM sites s JOIN users u ON s.owner_id = u.id WHERE s.slug = $1',
      [slug]
    );
    return result.rows[0];
  },

  async update({ id, slug, title }) {
    const result = await pool.query(
      'UPDATE sites SET slug = $1, title = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3 RETURNING *',
      [slug, title, id]
    );
    return result.rows[0];
  },

  async delete(id) {
    await pool.query('DELETE FROM sites WHERE id = $1', [id]);
  },

  async findAllPublic(limit = 20) {
    const result = await pool.query(
      `SELECT s.*, u.username as owner_username 
       FROM sites s
       JOIN users u ON s.owner_id = u.id
       ORDER BY s.created_at DESC
       LIMIT $1`,
      [limit]
    );
    return result.rows;
  },

  async countByOwner(ownerId) {
    const result = await pool.query(
      'SELECT COUNT(*) as count FROM sites WHERE owner_id = $1',
      [ownerId]
    );
    return parseInt(result.rows[0].count);
  },

  // File management
  async saveFile({ siteId, path, content, mimeType }) {
    const result = await pool.query(
      `INSERT INTO site_files (site_id, path, content, mime_type)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (site_id, path) 
       DO UPDATE SET content = $3, mime_type = $4, updated_at = CURRENT_TIMESTAMP
       RETURNING *`,
      [siteId, path, content, mimeType]
    );
    return result.rows[0];
  },

  async getFile(siteId, path) {
    const result = await pool.query(
      'SELECT * FROM site_files WHERE site_id = $1 AND path = $2',
      [siteId, path]
    );
    return result.rows[0];
  },

  async listFiles(siteId) {
    const result = await pool.query(
      'SELECT * FROM site_files WHERE site_id = $1 ORDER BY path',
      [siteId]
    );
    return result.rows;
  },

  async deleteFile(siteId, path) {
    await pool.query(
      'DELETE FROM site_files WHERE site_id = $1 AND path = $2',
      [siteId, path]
    );
  }
};

module.exports = Site;
