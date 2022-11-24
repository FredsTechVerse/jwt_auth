const mongoose = require("mongoose");
const { Schema } = mongoose;

// Creates a model for saving customer credentials to the database.
//==================================================================
const CredentialSchema = new Schema(
  {
    username: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      required: true,
      default: "new user",
    },
  },
  {
    timestamps: true,
  }
);

// // Hashes our password b4 saving to the DB
// //==========================================
// CredentialSchema.pre("save", async (req, res, next) => {
//   try {
//     const hashedPassword = await bcrypt.hash(this.password, 10);
//     this.password = hashedPassword;
//     next();
//   } catch (error) {
//     next(error);
//   }
// });

const CredentialModel = mongoose.model("Credential", CredentialSchema);

module.exports = CredentialModel;
