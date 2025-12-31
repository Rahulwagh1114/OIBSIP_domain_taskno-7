const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));


app.use(
  session({
    secret: "secret123",
    resave: false,
    saveUninitialized: false,
  })
);

// View Engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Database
const db = new sqlite3.Database("./users.db");

db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )
`);

// Routes
app.get("/", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", (req, res) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, 10);

  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hash],
    (err) => {
      if (err) return res.send("User already exists");
      res.redirect("/");
    }
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    (err, user) => {
      if (!user) return res.send("User not found");

      const isValid = bcrypt.compareSync(password, user.password);
      if (!isValid) return res.send("Wrong password");

      req.session.user = user.username;
      res.redirect("/dashboard");
    }
  );
});

app.get("/dashboard", (req, res) => {
  if (!req.session.user) return res.redirect("/");
  res.render("dashboard", { user: req.session.user });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// Server
app.listen(3000, () => {
  console.log("Server running at http://localhost:3000");
});
