const express = require('express');
const app = express();
const { pool } = require("./dbConfig");
const path = require('path');
const { request } = require('http');
const bcrypt = require('bcrypt');
const session = require('express-session');
const flash = require('express-flash');
const passport = require("passport");
const initializePassport = require("./passportConfig");

initializePassport(passport);

// environment variable
const PORT = process.env.PORT || 5000;

// middlewares
app.set('view engine', 'ejs');  // use ejs view engine to render ejs files
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(session({
  secret: 'this is the way',
  resave: false,  // if nothing is changed, do not resave
  saveUninitialized: false, // if empty, do not save
  maxAge: 30 * 60 * 1000, // 30 minutes
}))
app.use(passport.initialize());  // sets up passport to use in our app
app.use(passport.session());
app.use(flash());  // use flash messages
app.use(express.static(path.join(__dirname, 'public')));
app.use('/public', express.static('public'));

app.get('/', (req, res) => {
  res.render("index");
});

app.get('/users/register', checkAuthenticated, (req, res) => {
  res.render("register");
});

app.get('/users/login', checkAuthenticated, (req, res) => {
  res.render("login");
});

app.get('/users/adminlogin', checkAuthenticated, (req, res) => {
  res.render("adminlogin");
});

app.get('/users/dashboard', checkNotAuthenticated, (req, res) => {
  res.render("dashboard", { user: req.user.name });
});

app.get('/users/admindash', checkAuthorization, (req, res) => {
  res.render("admindash", { user: req.user.name });
});

app.get('/users/logout', checkNotAuthenticated, async (req, res) => {
  req.logOut();  // function within passport
  req.flash('success_msg', "Successfully logged out");
  res.redirect('/users/login');
})

app.post('/users/register', async (req, res) => {
  let {name, email, password, confirmpw} = req.body;

  console.log({
    name,
    email,
    password,
    confirmpw
  })

  let errors = [];  // form validation

  // check that no field(s) left empty
  if (!name || !email || !password || !confirmpw) {
    errors.push({ message: "Please fill in all fields" });
  }

  // check password length
  if (password.length < 8) {
    errors.push({ message: "Password must be at least 8 characters" });
  }

  // check password re-entered correctly
  if (password != confirmpw) {
    errors.push({ message: "Passwords do not match" })
  }

  // if any validation checks resulted in error
  if (errors.length > 0) {
    res.render("register", { errors });
  } else {  // passed validation checks
    // hash password
    let hashedPW = await bcrypt.hash(password, 10);  // hashed 10 times
    console.log(hashedPW);

    // check if email already exists
    pool.query(
      `SELECT * FROM bgcusers WHERE email=$1`, [email], (err, results) => {
        if (err) {
          throw err;
        } 

        console.log(results.rows);

        // email already in database
        if (results.rows.length > 0) {
          errors.push ({ message: "Email already registered" });
          res.render("register", { errors });
        } else {
          pool.query (
            `INSERT INTO bgcusers (name, email, password) 
            VALUES ($1, $2, $3) 
            RETURNING id, password`, [name, email, hashedPW], (err, results) => {
              if (err) {
                throw err;
              }
              console.log(results.rows);
              req.flash('success_msg', "Successfully registered, please log in");
              res.redirect("/users/login");
            }
          )
        }
      }
    );
  }
});


// regular user login
app.post(
  "/users/login", 
  passport.authenticate('local', {
    successRedirect: "/users/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true  // if authentication fails, pass in message (from err)
  })
);

// admin user login
app.post(
  "/users/adminlogin", 
  passport.authenticate('local', {
    successRedirect: "/users/admindash",
    failureRedirect: "/users/adminlogin",
    failureFlash: true  // if authentication fails, pass in message (from err)
  })
);

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {  // function within passport
    // redirects to dashboard if user IS authenticated
    return res.redirect('/users/dashboard');
  }
  next();  // otherwise, goes to next piece of middleware
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { 
    return next();
  }
  res.redirect('/users/login');
}


// if user is admin
function checkAuthorization(req, res, next) {
  if (req.isAuthenticated() && (req.user.admin = 't')) {
      return next();
  }
  return res.redirect('/users/dashboard');
}

app.listen(PORT, () => console.log(`Listening on ${ PORT }`));
