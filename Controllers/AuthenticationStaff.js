const jwt = require("jsonwebtoken");
// CUSTOM FUNCTIONS
function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
}

function generateRefreshToken(user) {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "1y" });
}
// SOLE MISSION IS TO DESTRUCTURE THE PAYLOAD UPON SUCCESSFUL COMPARISON.
//=========================================================================
function authenticateToken(req, res, next) {
  const authHeader = req.headers[`authorization`];
  const token = authHeader && authHeader.split(" ")[1];
  console.log(`Auth Token ${token}`);
  if (token == null) {
    return res.sendStatus(401);
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, payload) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = payload; //Tunaskuma the payload data into the user object kwa req.
    next();
  });
}

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  authenticateToken,
};
