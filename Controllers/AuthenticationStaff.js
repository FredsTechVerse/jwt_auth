const jwt = require("jsonwebtoken");
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

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  authenticateToken,
};
