import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import passport from "passport";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";
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
  picture: String,
  role: { type: String, default: "customer" }
},{versionKey : false, collection : "OAuthUsers"});

const User = mongoose.model("User", userSchema);

// ====== MONGOOSE SELLER MODEL ======
const sellerSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    name: String,
    email: String,
    shopName: { type: String, required: true },
    shopType: { type: String, required: true },
    shopPhoto: String, // Cloudinary URL
    shopLocation: String,
  },
  { versionKey: false, collection: "Sellers" }
);

const Seller = mongoose.model("Seller", sellerSchema);


// ====== PRODUCT MODEL ======
const productSchema = new mongoose.Schema(
  {
    sellerId: { type: mongoose.Schema.Types.ObjectId, ref: "Seller", required: true },
    shopId: { type: mongoose.Schema.Types.ObjectId, ref: "Sellers", required: true },
    shopName: String,
    shopType: String,
    brand: String,
    model: String,
    color: String,
    storage: String,
    ram: String,
    price: Number,
    image: String, // Cloudinary URL
  },
  { versionKey: false, collection: "AllProducts" }
);

const Product = mongoose.model("Product", productSchema);


// ====== CLOUDINARY CONFIG ======
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "shops",   // sab shop images ek folder me
    allowed_formats: ["jpg", "png", "jpeg", "webp"]
  },
});

const upload = multer({ storage });

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
        picture: profile.photos[0].value,
        role: "customer"
      });
      return done(null, newUser);
    } catch (err) {
      return done(err, null);
    }
  }
));

// ====== AUTH ROUTES ======
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { session: false }),
  (req, res) => {
    const token = jwt.sign({ id: req.user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d"
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: false, // HTTPS par true
      sameSite: "lax",
      maxAge: 24*60*60*1000
    });

    res.redirect(`${process.env.FRONTEND_URL}/profile`);
  }
);

app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logged out" });
});

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

// ====== SELLER ROUTE (with image upload) ======
app.post("/seller/register", upload.single("shopPhoto"), async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) return res.status(404).json({ message: "User not found" });

    const existingSeller = await Seller.findOne({ userId: user._id });
    if (existingSeller) {
      return res.status(400).json({ message: "You are already a seller" });
    }

    const { shopName, shopType, shopLocation } = req.body;

    // shop photo ka URL multer-cloudinary se aayega
    const shopPhoto = req.file ? req.file.path : null;

    const newSeller = await Seller.create({
      userId: user._id,
      name: user.name,
      email: user.email,
      shopName,
      shopType,
      shopPhoto,
      shopLocation,
    });

    user.role = "seller";
    await user.save();

    res.json({ message: "Seller registered successfully", seller: newSeller });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ====== GET SELLER DETAILS ======
app.get("/seller/me", async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user || user.role !== "seller") {
      return res.status(403).json({ message: "Access denied" });
    }

    const seller = await Seller.findOne({ userId: user._id });
    if (!seller) return res.status(404).json({ message: "Seller not found" });

    res.json({ seller });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ====== ADD PRODUCT ROUTE ======
app.post("/product/add", upload.single("image"), async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || user.role !== "seller") {
      return res.status(403).json({ message: "Access denied" });
    }

    const seller = await Seller.findOne({ userId: user._id });
    if (!seller) return res.status(404).json({ message: "Seller not found" });

    const { brand, model, color, storage, ram, price } = req.body;
    const image = req.file ? req.file.path : null;

    const newProduct = await Product.create({
      sellerId: user._id,
      shopId: seller._id,
      shopName: seller.shopName,
      shopType: seller.shopType,
      brand,
      model,
      color,
      storage,
      ram,
      price,
      image,
    });

    res.json({ message: "Product added successfully", product: newProduct });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ====== GET ALL PRODUCTS ======
app.get("/products", async (req, res) => {
  try {
    const products = await Product.find().sort({ _id: -1 }); // latest first
    res.json({ products });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ====== GET CURRENT SELLER PRODUCTS ======
app.get("/products/my", async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user || user.role !== "seller") {
      return res.status(403).json({ message: "Access denied" });
    }

    const seller = await Seller.findOne({ userId: user._id });
    if (!seller) return res.status(404).json({ message: "Seller not found" });

    const products = await Product.find({ sellerId: user._id }).sort({ _id: -1 });
    res.json({ products });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ====== UPDATE PRODUCT ======
app.put("/product/update/:id", upload.single("image"), async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || user.role !== "seller") {
      return res.status(403).json({ message: "Access denied" });
    }

    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Product not found" });

    // Check if the product belongs to the seller
    if (!product.sellerId.equals(user._id)) {
      return res.status(403).json({ message: "You cannot update this product" });
    }

    const { brand, model, color, storage, ram, price } = req.body;

    // Update product fields
    if (brand) product.brand = brand;
    if (model) product.model = model;
    if (color) product.color = color;
    if (storage) product.storage = storage;
    if (ram) product.ram = ram;
    if (price) product.price = price;
    if (req.file) product.image = req.file.path; // Update image if uploaded

    await product.save();
    res.json({ message: "Product updated successfully", product });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ====== DELETE PRODUCT ======
app.delete("/product/delete/:id", async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || user.role !== "seller") {
      return res.status(403).json({ message: "Access denied" });
    }

    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Product not found" });

    // Only allow seller to delete own product
    if (!product.sellerId.equals(user._id)) {
      return res.status(403).json({ message: "You cannot delete this product" });
    }

    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: "Product deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});



// ====== DB CONNECT ======
mongoose.connect(process.env.MONGO_URI).then(() => {
  console.log("MongoDB connected");
}).catch(err => console.log(err));

app.listen(process.env.PORT, () => console.log(`Server running on ${process.env.PORT}`));
