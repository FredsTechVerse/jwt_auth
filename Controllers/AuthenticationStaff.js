const jwt = require("jsonwebtoken");
// CUSTOM FUNCTIONS
function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "2m" });
}

function generateRefreshToken(user) {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "1y" });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers[`authorization`];
  const token = authHeader && authHeader.split(" ")[1];
  console.log(`Auth Token ${token}`);
  if (token == null)
    return res.sendStatus(401).json({ message: "Gerrout of here mehn!" });
  console.log(`Refresh Token Secret : ${process.env.REFRESH_TOKEN_SECRET}`);
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, payload) => {
    if (err) {
      console.log(err);
      return res.sendStatus(403);
    }
    req.user = payload;
    next();
  });
}

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  authenticateToken,
};
