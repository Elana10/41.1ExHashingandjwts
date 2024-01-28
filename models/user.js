/** User class for message.ly */

const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");
const db = require("../db");
const ExpressError = require("../expressError");
const { ensureLoggedIn, ensureCorrectUser} = require('../middleware/auth');
const bcrypt = require('bcrypt');

/** User of the site. */

class User {
  constructor(username, first_name, last_name, phone, join_at, last_login_at){
    this.username = username;
    this.first_name = first_name;
    this.last_name = last_name;
    this.phone = phone;
    this.join_at = join_at;
    this.last_login_at = last_login_at;
  }

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */
  static async register({username, password, first_name, last_name, phone}) {
    try{
      if(!username || !password || !first_name || !last_name || !phone){
        throw new ExpressError("Please complete all required fields", 400)
      }
      //hash PW
      const hashedPW = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);

      //save to DB
      const result = await db.query(
        `INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
        VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING username, password, first_name, last_name, phone`, 
        [username, hashedPW, first_name, last_name, phone]);
      return result.rows[0]
    } catch(e) {
      // if (e.code === '23505'){
      //   return new ExpressError("Username taken. Please pick another!", 400)
      // }
      return e;
    }

  }

  /** Authenticate: is this username/password valid? Returns boolean. */
  static async authenticate(username, password) {
    try{
      const results = await db.query(
        `SELECT username, password FROM users WHERE username = $1`, [username]);
        const user = results.rows[0];
        if (user) {
          if (await bcrypt.compare(password, user.password)){
            this.updateLoginTimestamp(username)
            return true
          }
        }
        return false      
    } catch(e) {
      return e;
    }
  }

  /** Update last_login_at for user */
  static async updateLoginTimestamp(username) {
    const results = await db.query(
    `UPDATE users 
    SET last_login_at = CURRENT_TIMESTAMP
    WHERE username = $1`,
    [username]
  )    
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */
  static async all() {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at
      FROM users`);

    const users = results.rows.map( u => new User(u.username, u.first_name, u.last_name, u.phone));
    return users;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */
  static async get(username) {
    try{
      const results = await db.query(
        `SELECT username, first_name, last_name, phone, join_at, last_login_at FROM users WHERE username = $1`,
        [username] 
      );
      const u = results.rows[0];
      if (!u){
        throw new ExpressError('User not found', 404);
      }
      return new User(u.username, u.first_name, u.last_name, u.phone, u.join_at, u.last_login_at)
    } catch(e) {
      return e;
    }
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */
  static async messagesFrom(username) {
    try{
      const results = await db.query(
        `SELECT m.id, m.body, m.sent_at, m.read_at, u.username, u.first_name, u.last_name, u.phone 
        FROM messages AS m
        LEFT JOIN users AS u
        ON m.to_username = u.username
        WHERE m.from_username = $1`,
        [username]
      );
      const messages = results.rows.map( r => ({
        id : r.id,
        body : r.body,
        sent_at : r.sent_at, 
        read_at : r.read_at,
        to_user : {
          username : r.username, 
          first_name : r.first_name,
          last_name : r.last_name,
          phone : r.phone
        }
      }))

      return messages;
    } catch(e){
      return e;
    }
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */
  static async messagesTo(username) {
    try{
      const results = await db.query(
        `SELECT m.id, m.body, m.sent_at, m.read_at, u.username, u.first_name, u.last_name, u.phone 
        FROM messages AS m
        LEFT JOIN users AS u
        ON m.from_username = u.username
        WHERE m.to_username = $1`,
        [username]
      );
      const messages = results.rows.map( r => ({
        id : r.id,
        body : r.body,
        sent_at : r.sent_at, 
        read_at : r.read_at,
        from_user : {
          username : r.username, 
          first_name : r.first_name,
          last_name : r.last_name,
          phone : r.phone
        }
      }))
      return messages;    
    } catch(e){
      return e;
    }
  }
}


module.exports = User;