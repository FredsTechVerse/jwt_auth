const jwt = require("jsonwebtoken");
// CUSTOM FUNCTIONS
function generateAccessToken(userData) {
  return jwt.sign(userData, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "1m", //Usually shorter for sercurity reasons.
  });
}

function generateRefreshToken(userData) {
  return jwt.sign(userData, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "10m", //Should have a longer expiration time.
  });
}
// SOLE MISSION IS TO DESTRUCTURE THE PAYLOAD UPON SUCCESSFUL COMPARISON.
//=========================================================================
// Verify & Decrypts Access token
function authenticateToken(req, res, next) {
  const authHeader = req.headers[`authorization`];
  const token = authHeader && authHeader.split(" ")[1]; //
  console.log(`Auth Token ${token}`);
  if (token == null) {
    return res.sendStatus(401);
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, payload) => {
    if (err) {
      //BREAKING DOWN THE ERRORS FURTHER.
      if (err.name == "TokenExpiredError") {
        // We automatically request for a new access token & refresh token.
        console.log(`${JSON.stringify(err)}`);
        return res.status(403).send(err.message);
      } else if (err.name == "JsonWebTokenError") {
        res.status(403).send(err.message);
      }
    }
    req.user = payload; //Tunaskuma the payload data into the user object if we can prove that the data has not been altered,
    next();
  });
}

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  authenticateToken,
};
