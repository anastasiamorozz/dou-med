const express = require("express");
const passport = require('passport');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const session = require('express-session');
const crypto = require('crypto');
const app = express();
const cors = require('cors');
require('dotenv').config();

app.use(cors());

const sessionSecret = crypto.randomBytes(32).toString('hex');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(session({ secret: sessionSecret, resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());


app.get('/', (req, res) => {
    res.send("Server is running");
});

app.use(express.json()); 

const port = process.env.PORT || 8080;
app.listen(port, () => {
    console.log('server running on port', port);
});
