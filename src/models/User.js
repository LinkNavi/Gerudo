// models/User.js
const { pool } = require("../db");

const User = {
  async create({ username, passwordHash }) {
    const result = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING *',
      [username, passwordHash]
    );
    return result.rows[0];
  },

  async findByUsername(username) {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );
    return result.rows[0];
  },

  async findById(id) {
    const result = await pool.query(
      'SELECT id, username, created_at FROM users WHERE id = $1',
      [id]
    );
    return result.rows[0];
  },

  async listSites(userId) {
    const result = await pool.query(
      'SELECT * FROM sites WHERE owner_id = $1 ORDER BY created_at DESC',
      [userId]
    );
    return result.rows;
  }
};

module.exports = User;
