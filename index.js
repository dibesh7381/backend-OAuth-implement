import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import passport from "passport";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

dotenv.config();
const app = express();

// ====== MIDDLEWARE ======
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));
app.use(cookieParser());
app.use(express.json());
app.use(passport.initialize());

// ====== MONGOOSE USER MODEL ======
const userSchema = new mongoose.Schema({
  googleId: { type: String, required: true },
  name: String,
  email: String,
  picture: String
},{versionKey : false, collection : "OAuthUsers"});
const User = mongoose.model("User", userSchema);

// ====== PASSPORT GOOGLE STRATEGY ======
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.BACKEND_URL}/auth/google/callback`
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const existingUser = await User.findOne({ googleId: profile.id });
      if (existingUser) return done(null, existingUser);

      const newUser = await User.create({
        googleId: profile.id,
        name: profile.displayName,
        email: profile.emails[0].value,
        picture: profile.photos[0].value
      });
      return done(null, newUser);
    } catch (err) {
      return done(err, null);
    }
  }
));

// ====== AUTH ROUTES ======

// 1. Start Google OAuth
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// 2. Google OAuth callback
app.get("/auth/google/callback",
  passport.authenticate("google", { session: false }),
  (req, res) => {
    // Generate JWT
    const token = jwt.sign({ id: req.user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d"
    });

    // Send token in httpOnly cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: false, // set true if HTTPS
      sameSite: "lax",
      maxAge: 24*60*60*1000
    });

    // Redirect frontend after login
    res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
  }
);

// 3. Logout
app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logged out" });
});

// 4. Protected route example
app.get("/profile", async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    res.json({ user });
  } catch (err) {
    res.status(401).json({ message: "Unauthorized" });
  }
});

// ====== CONNECT MONGODB & START SERVER ======
mongoose.connect(process.env.MONGO_URI).then(() => {
  console.log("MongoDB connected");
}).catch(err => console.log(err));

app.listen(process.env.PORT, () => console.log(`Server running on ${process.env.PORT}`));
