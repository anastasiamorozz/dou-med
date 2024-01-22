const { createSecretToken } = require('../util/SecretToken.js');
const bcrypt = require('bcrypt');
const db = require('../db')

class UserController {
    async createUser(req, res){
        try {
            const { username, email, phone, tg, password } = req.body;
        
            const existingUser = await db.query('SELECT * FROM users WHERE username = $1 OR email = $2 OR phone = $3 OR tg = $4', [username, email, phone, tg]);
        
            if (existingUser.rows.length > 0) {
              return res.status(409).json({ error: 'User with this username or email already exists' });
            }
        
            const hashedPassword = await bcrypt.hash(password, 10);
        
            const newUser = await db.query('INSERT INTO users (username, email, phone, tg, password) VALUES ($1, $2, $3, $4, $5) RETURNING *', [username, email, phone, tg, hashedPassword]);
        
            const userId = newUser.rows[0].id;
            const token = createSecretToken(userId);

            res.status(201).json({token});
          } catch (error) {
            console.error('Error during registration:', error);
            res.status(500).json({ error: 'Internal Server Error' });
          }
    }

    async loginUser(req, res) {
        try {
          const { username, password } = req.body;
      
          const user = await db.query('SELECT * FROM users WHERE username = $1', [username]);
      
          if (user.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid username' });
          }
        
          const isValidPassword = await bcrypt.compare(password, user.rows[0].password);
      
          if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid password' });
          }
      
          const userId = user.rows[0].id;
          const token = createSecretToken(userId);
      
          res.status(200).json({ token, userId, username });
        } catch (error) {
          console.error('Error during login:', error);
          res.status(500).json({ error: 'Internal Server Error' });
        }
      }

    async getUsers(req, res){
        const users = await db.query('SELECT * FROM Users')
        return res.status(200).send({users: users.rows})
    }

    async getOneUser(req, res){
        const userId = parseInt(req.params.id);
        if(!userId){
            return res.status(400).send({error: 'Invalid ID'}); 
        }
        const user = await db.query("SELECT * FROM Users WHERE id=$1", [userId]);
        return res.status(200).send(user.rows);
    }

    async updateUsername(req, res){
      const { username } = req.body;
      const userId = req.params.id;
    
      try {
        const checkUsername = await db.query('SELECT * FROM Users WHERE username = $1 AND id != $2', [username, userId]);
    
        if (checkUsername.rows.length > 0) {
          return res.status(409).json({ error: 'Username is already taken' });
        }
    
        const updateResult = await db.query('UPDATE Users SET username = $1 WHERE id = $2 RETURNING *', [username, userId]);
    
        if (updateResult.rows.length === 0) {
          return res.status(404).json({ error: 'User not found' });
        }
    
        res.status(200).json({ success: true, message: 'Username updated successfully', username});
      } catch (error) {
        console.error('Error during username update:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    
    }

    async updateEmail(req, res){
        const { email } = req.body;
        const userId = req.params.id;
      
        try {
          const checkEmail = await db.query('SELECT * FROM Users WHERE email = $1 AND id != $2', [email, userId]);
      
          if (checkEmail.rows.length > 0) {
            return res.status(409).json({ error: 'Email is already taken' });
          }
      
          const updateResult = await db.query('UPDATE Users SET email = $1 WHERE id = $2 RETURNING *', [email, userId]);
      
          if (updateResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
          }
      
          res.status(200).json({ success: true, message: 'Email updated successfully', email});
        } catch (error) {
          console.error('Error during username update:', error);
          res.status(500).json({ error: 'Internal Server Error' });
        }
      
      }

      async updatePhone (req, res){
        const { phone } = req.body;
        const userId = req.params.id;
      
        try {
          const checkPhone = await db.query('SELECT * FROM Users WHERE phone = $1 AND id != $2', [phone, userId]);
      
          if (checkPhone.rows.length > 0) {
            return res.status(409).json({ error: 'Phone is already taken' });
          }
      
          const updateResult = await db.query('UPDATE Users SET phone = $1 WHERE id = $2 RETURNING *', [phone, userId]);
      
          if (updateResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
          }
      
          res.status(200).json({ success: true, message: 'Phone updated successfully', email});
        } catch (error) {
          console.error('Error during username update:', error);
          res.status(500).json({ error: 'Internal Server Error' });
        }
      
      }

      async updateTelegtam (req, res){
        const { tg } = req.body;
        const userId = req.params.id;
      
        try {
          const checkTelegram = await db.query('SELECT * FROM Users WHERE tg = $1 AND id != $2', [tg, userId]);
      
          if (checkTelegram.rows.length > 0) {
            return res.status(409).json({ error: 'Telegram username is already taken' });
          }
      
          const updateResult = await db.query('UPDATE Users SET tg = $1 WHERE id = $2 RETURNING *', [tg, userId]);
      
          if (updateResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
          }
      
          res.status(200).json({ success: true, message: 'Telegram username updated successfully', email});
        } catch (error) {
          console.error('Error during username update:', error);
          res.status(500).json({ error: 'Internal Server Error' });
        }
      
      }

    async updatePassword(req, res){
      const { currentPassword, password } = req.body;
      const userId = req.params.id;
    
      try {
        const getOldPassword = await db.query('SELECT password FROM Users WHERE id = $1', [userId]);

        const comparePasswords = await bcrypt.compare(currentPassword, getOldPassword.rows[0].password);
    
        if (!comparePasswords) {
          return res.status(409).json({ error: 'Curent password is incorrect' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
    
        const updateResult = await db.query('UPDATE Users SET password = $1 WHERE id = $2 RETURNING *', [hashedPassword, userId]);
    
        if (updateResult.rows.length === 0) {
          return res.status(404).json({ error: 'User not found' });
        }
    
        res.status(200).json({ success: true, message: 'Password updated successfully'});
      } catch (error) {
        console.error('Error during password update:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    
    }

    async deleteUser(req, res){
        const userId = req.user.id;
        try{
            const result = await db.query("DELETE FROM Users WHERE id=$1", [userId]);

            res.status(200).json({ success: true, message: 'User deleted successfully'});
        }catch(error){
            console.log(error);
            res.status(500).json({ error: "Server error"});
        }
    }
}

module.exports = new UserController();