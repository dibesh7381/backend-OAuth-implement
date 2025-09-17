import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import jwt from "jsonwebtoken";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

dotenv.config();
const app = express();

// ======= MIDDLEWARES =======
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));
app.use(express.json());
app.use(passport.initialize());

// ======= MONGODB CONNECTION =======
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("✅ MongoDB connected"))
.catch(err => console.log(err));

// ======= USER MODEL =======
const userSchema = new mongoose.Schema({
  googleId: { type: String, required: true },
  name: String,
  email: String,
  role : {type : String, default : "user"}
}, { versionKey: false });
const User = mongoose.model("User", userSchema);

// ======= PASSPORT SETUP =======
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ googleId: profile.id });
      if (!user) {
        user = await User.create({
          googleId: profile.id,
          name: profile.displayName,
          email: profile.emails[0].value
        });
      }
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }
));

// ======= ROUTES =======

// Google OAuth login
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

// Google OAuth callback
app.get("/auth/google/callback",
  passport.authenticate("google", { session: false, failureRedirect: "/" }),
  (req, res) => {
    const token = jwt.sign(
      { id: req.user._id, name: req.user.name, email: req.user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    // Redirect frontend with token in URL
    res.redirect(`${process.env.FRONTEND_URL}/dashboard?token=${token}`);
  }
);


// Protected route example
// Protected route example with inline JWT verification using a variable
app.get("/auth/user", (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) return res.status(401).json({ message: "Missing token" });

  const token = authHeader.split(" ")[1];

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
  res.json({ success: true, user: decoded });
});


// ======= START SERVER =======
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
