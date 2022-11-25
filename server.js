const mongoose = require("mongoose");
const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

// CONNECTING TO MONGODB
//=======================
const connection = process.env.CONNECTION_URL;
mongoose.connect(connection, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// CONNECTION TEST
//=================
const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error: "));
db.once("open", function () {
  console.log("The database is ready.");
});

// ESSENTIAL MIDDLEWARES
//=======================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// ROUTES IMPORTATION
//====================
const AuthenticateRoute = require("./Routes/AuthRoute");

// ROUTES DEFINATION
//===================
app.use("/auth", AuthenticateRoute);

app.get("/", (req, res) => {
  res
    .status(200)
    .json({ message: "We are officially live @jwt_implementation" });
});

app.listen(3000, () => {
  console.log("The normal server is officially live @jwt_implementation");
});
