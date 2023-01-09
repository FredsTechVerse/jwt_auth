const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const {
  generateAccessToken,
  generateRefreshToken,
  authenticateToken,
} = require("../Controllers/AuthenticationStaff");
require("dotenv").config();
const jwt = require("jsonwebtoken");

const Credentials = require("../Models/Credentials");

// DATA TO BE ACCESSED.
//=====================
const posts = [
  {
    username: "Kyle",
    title: "Post 1",
  },
  {
    username: "Benson",
    role: [0535, 0534],
    title: "Hello this is my info as Benson.",
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

// CONSUMING CONTENT.
//===================
router.get("/posts", authenticateToken, (req, res) => {
  console.log(`Payload to be utilized ${req.user}`);
  res.json(posts.filter((post) => post.username === req.user.name));
});
// RENEWING THE ACCESS TOKENS BASED ON THE REFRESH TOKEN
//=======================================================
router.post("/token", (req, res) => {
  const refreshToken = req.body.refreshToken;
  //   Trap 1 : Checks if the refresh token is a bluff/empty.
  if (refreshToken == null) {
    return res.status(401).json({ message: "No refresh token received." });
  }
  // Trap 2 : Compares the refresh tokens
  if (!refreshTokens.includes(refreshToken)) {
    return res
      .status(403)
      .json({ message: "Refresh token has not been found." });
  }
  // We need to delete the previous refresh token for security reasons.
  //   Trap 3 : Regenerates our short term access token (Its all about verifying payload and extracting info
  // again to be used in the regeneration of the access token.)
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, payload) => {
    if (err)
      return res.status(403).json({
        message:
          "We have your refresh token but somehow we are encountering some issues.",
      });
    const accessToken = generateAccessToken({ name: payload.name });
    const refreshToken = generateRefreshToken({ name: payload.name });
    res.json({ accessToken, refreshToken });
  });
});

// GENERATES THE REFRESH & ACCESS TOKENS
//========================================
router.post("/register", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    let credentials = {
      username: req.body.username,
      password: hashedPassword,
    };
    const user = await Credentials.create(credentials);
    user.save();
    res.status(201).json({ message: "User has been created successfuly." });
  } catch (error) {
    res.status(500).json({ message: error });
  }
});

// GENERATES THE REFRESH & ACCESS TOKENS
//========================================
router.post("/login", async (req, res) => {
  console.log(req.body.username);

  // Retrieving user credentials from our database.
  let UserData = await Credentials.findOne({ username: req.body.username });
  console.log(UserData);
  if (UserData == null) {
    res.status(400).json({ message: "User not found" });
  } else {
    const { username, role, password } = UserData;

    // Step 2 : Comparing passwords using bcrypt compare function.
    try {
      if (await bcrypt.compare(req.body.password, password)) {
        // Step 2 : Generating User Payload, if the user is valid.
        const user = { name: username, role }; //Our payload.
        // Step 3 : Generating the access & refresh tokens
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);
        //Step 4 : Saving a copy of the refresh token to our database.
        refreshTokens.push(refreshToken);
        //Step 5 : Sending refresh and access token to client.
        res.status(200).json({ accessToken, refreshToken });
      } else {
        res.status(401).json({ message: "The passwords do not match." });
      }
    } catch (err) {
      console.log(err);
      res
        .status(500)
        .json({ message: "Error occured while verifying tokens." });
    }
  }
});

// DELETES THE REFRESH TOKENS IN OUR DATABASE.
//=============================================
router.delete("/logout", (req, res) => {
  if (!refreshTokens.includes(req.body.token)) {
    return res.sendStatus(403).send("Huwezi nicheza huskii...");
  }
  refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
  res.sendStatus(204).send("All clear");
});

module.exports = router;
