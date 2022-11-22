require("dotenv").config();
const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
// ESSENTIAL MIDDLEWARES
//=======================
app.use(express.json());

// DATA TO BE ACCESSED.
//=====================
const posts = [
  {
    username: "Kyle",
    title: "Post 1",
  },
  {
    username: "Alfred",
    title: "Post 2",
  },
  {
    username: "Joan",
    title: "Post 3",
  },
];

// REFRESH TOKEN STORAGE.
//=======================
let refreshTokens = [];

// CUSTOM FUNCTIONS
function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "45s" });
}

function generateRefreshToken(user) {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers[`authorization`];
  const token = authHeader && authHeader.split(" ")[1];
  console.log(`Auth Token ${token}`);
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      console.log(err);
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

// OUR ROUTES
//===========

app.get("/", (req, res) => {
  res.status(200).send("We are officially live.");
});

// CONSUMING CONTENT.
//===================
app.get("/posts", authenticateToken, (req, res) => {
  res.json(posts.filter((post) => post.username === req.user.name));
});
// RENEWING THE ACCESS TOKENS BASED ON THE REFRESH TOKEN
//=======================================================
app.post("/token", (req, res) => {
  const refreshToken = req.body.refreshToken;
  //   Trap 1 : Checks if the refresh token is a bluff/empty.
  if (refreshToken == null) {
    return res.sendStatus(401);
  }
  // Trap 2 : Compares the refresh tokens
  if (!refreshTokens.includes(refreshToken)) {
    return res.sendStatus(403);
  }

  //   Trap 3 : Regenerates our short term access token
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken: accessToken });
  });
});
// GENERATES THE REFRESH & ACCESS TOKENS
//========================================
app.post("/login", (req, res) => {
  const username = req.body.username;
  const user = { name: username }; //Our payload.

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  //Saving the refresh token to our database.
  //=========================================
  refreshTokens.push(refreshToken);

  //Sending our our response to client
  //=====================================
  res.json({ accessToken, refreshToken });
});

// DELETES THE REFRESH TOKENS IN OUR DATABASE.
//=============================================
app.delete("/logout", (req, res) => {
  if (!refreshTokens.includes(req.body.token)) {
    return res.sendStatus(403).send("Unanichezea akili kijana");
  }
  refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
  res.sendStatus(204).send("All clear");
});

app.listen(3000, () => {
  console.log("The normal server is officially live.");
});
