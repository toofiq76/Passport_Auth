const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;

const app = express();

// ================= MIDDLEWARES =================
app.use(express.json());
app.use(cookieParser());

app.use(
  session({
    secret: "superSecretKey123",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true }
  })
);

app.use(passport.initialize());
app.use(passport.session());

// ================= FAKE DATABASE =================
const users = []; // { id, username, password?, googleId?, facebookId? }

// ================= PASSPORT SESSION ===============
// ==
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = users.find(u => u.id === id);
  done(null, user);
});

// ================= GOOGLE STRATEGY =================
// UNCOMMENT AFTER ADDING YOUR GOOGLE OAUTH CREDENTIALS
// passport.use(
//   new GoogleStrategy(
//     {
//       clientID: "YOUR_GOOGLE_CLIENT_ID",
//       clientSecret: "YOUR_GOOGLE_CLIENT_SECRET",
//       callbackURL: "http://localhost:3000/auth/google/callback"
//     },
//     (accessToken, refreshToken, profile, done) => {
//       let user = users.find(u => u.googleId === profile.id);
//
//       if (!user) {
//         user = {
//           id: users.length + 1,
//           username: profile.displayName,
//           googleId: profile.id
//         };
//         users.push(user);
//       }
//
//       done(null, user);
//     }
//   )
// );

// ================= FACEBOOK STRATEGY =================
// UNCOMMENT AFTER ADDING YOUR FACEBOOK APP CREDENTIALS
// passport.use(
//   new FacebookStrategy(
//     {
//       clientID: "YOUR_FACEBOOK_APP_ID",
//       clientSecret: "YOUR_FACEBOOK_APP_SECRET",
//       callbackURL: "http://localhost:3000/auth/facebook/callback",
//       profileFields: ["id", "displayName", "emails"]
//     },
//     (accessToken, refreshToken, profile, done) => {
//       let user = users.find(u => u.facebookId === profile.id);
//
//       if (!user) {
//         user = {
//           id: users.length + 1,
//           username: profile.displayName,
//           facebookId: profile.id
//         };
//         users.push(user);
//       }
//
//       done(null, user);
//     }
//   )
// );

// ================= LOCAL REGISTER =================
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const exists = users.find(u => u.username === username);
  if (exists) return res.status(400).json({ message: "User already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);

  users.push({
    id: users.length + 1,
    username,
    password: hashedPassword
  });

  res.json({ message: "Registration successful" });
});

// ================= LOCAL LOGIN =================
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username && u.password);
  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ message: "Invalid credentials" });

  req.session.user = { id: user.id };
  res.json({ message: "Login successful" });
});

// ================= GOOGLE ROUTES =================
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/dashboard");
  }
);

// ================= FACEBOOK ROUTES =================
app.get("/auth/facebook",
  passport.authenticate("facebook")
);

app.get("/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/dashboard");
  }
);

// ================= AUTH MIDDLEWARE =================
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated() || req.session.user) return next();
  res.status(401).json({ message: "Unauthorized" });
}

// ================= PROTECTED ROUTE =================
app.get("/dashboard", isAuthenticated, (req, res) => {
  const user = req.user || users.find(u => u.id === req.session.user?.id);
  const userResult = JSON.stringify(user)

  res.send(
    `<h1>Welcome to dashboard</h1>
    <p>${userResult}</p>
    <form action="http://localhost:3000/logout" method="post">
    <input type="submit" value="logout">
    </form>`
     
    
  );
});

// ================= LOGOUT =================
app.post("/logout", (req, res) => {
  // req.logout?.(() => {});
  req.session.destroy(err => {
    if (err) return res.status(500).json({ message: "Logout failed" });
    res.clearCookie("connect.sid");
    res.json({ message: "Logout successful" });
  });
});

// ================= LOGIN PAGE (CHOICE) =================
app.get("/login", (req, res) => {
  res.send(`
    <h2>Login</h2>
    <h3>Local Login</h3>
    <p>POST /login</p>
    <h3>Social Login</h3>
    <a href="/auth/google">Login with Google</a><br/>
    <a href="/auth/facebook">Login with Facebook</a>
  `);
});

// ================= START SERVER =================
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
