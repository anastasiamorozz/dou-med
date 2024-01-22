const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const crypto = require('crypto');
const jwtSecretKey = crypto.randomBytes(32).toString('hex');

const pool = new Pool({
    user: "postgres",
    password: '123456',
    host: "localhost",
    port: 5432,
    database: "med"
});

// Локальна стратегія Passport
passport.use(new LocalStrategy(
  { usernameField: 'username' },
  async (username, password, done) => {
    try {
      const result = await pool.query('SELECT * FROM Users WHERE username = $1', [username]);

      if (result.rows.length > 0) {
        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password);

        if (match) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password.' });
        }
      } else {
        return done(null, false, { message: 'User not found.' });
      }
    } catch (err) {
      return done(err);
    }
  }
));

// JWT стратегія Passport
passport.use(new JwtStrategy(
  {
    jwtFromRequest: req => req.cookies.jwt, // або з іншого місця, де ви зберігаєте токен
    secretOrKey: jwtSecretKey,
  },
  (jwtPayload, done) => {
    // Можливо, здійснити перевірку користувача у базі даних тут
    return done(null, jwtPayload.user);
  }
));

// Серіалізація та десеріалізація користувача
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query('SELECT * FROM Users WHERE id = $1', [id]);
    const user = result.rows[0];
    done(null, user);
  } catch (err) {
    done(err);
  }
});