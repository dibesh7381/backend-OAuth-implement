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
// ====== PRODUCT MODEL ======
const productSchema = new mongoose.Schema(
  {
    sellerId: { type: mongoose.Schema.Types.ObjectId, ref: "Seller", required: true },
    shopId: { type: mongoose.Schema.Types.ObjectId, ref: "Sellers", required: true },
    shopName: { type: String, default: null },
    shopType: { type: String, default: null },

    // Common fields
    brand: { type: String, default: null },
    model: { type: String, default: null },
    productType: { type: String, default: null }, // Home appliance category: TV, AC, Fridge, Cooler
    color: { type: String, default: null },
    price: { type: Number, default: null },
    image: { type: String, default: null }, // Cloudinary URL

    // Mobile-specific fields
    storage: { type: String, default: null },
    ram: { type: String, default: null },
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
    const token = jwt.sign({ id: req.user._id, role: req.user.role }, process.env.JWT_SECRET, {
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
    console.log("======== ADD PRODUCT REQUEST ========");
    console.log("REQ.BODY:", req.body);
    console.log("REQ.FILE:", req.file);

    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || user.role !== "seller") {
      return res.status(403).json({ message: "Access denied" });
    }

    const seller = await Seller.findOne({ userId: user._id });
    if (!seller) return res.status(404).json({ message: "Seller not found" });

    // Safely destructure and provide defaults
    const {
      brand = null,
      model = null,
      productType = null,
      color = null,
      storage = null,
      ram = null,
      price = null
    } = req.body;

    const image = req.file ? req.file.path : null;

    const newProduct = await Product.create({
      sellerId: seller._id,
      shopId: seller._id,
      shopName: seller.shopName,
      shopType: seller.shopType,
      brand,
      model,
      productType,
      color,
      storage,
      ram,
      price,
      image,
    });

    console.log("NEW PRODUCT CREATED:", newProduct);

    res.json({ message: "Product added successfully", product: newProduct });

  } catch (err) {
    console.error("ERROR IN ADD PRODUCT:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// ====== GET ALL PRODUCTS ======
app.get("/products", async (req, res) => {
  try {
    const token = req.cookies.token; // cookie se token lena
    let userRole = "customer"; // default

    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        userRole = decoded.role || "customer"; // token me role ho to use karo
      } catch (err) {
        console.log("Invalid token");
      }
    }

    const products = await Product.find().sort({ _id: -1 }); // latest first
    res.json({ products, userRole }); // client ko role bhi bhej do
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

    const products = await Product.find({ sellerId: seller._id }).sort({ _id: -1 });
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

    const seller = await Seller.findOne({ userId: user._id });
    if (!seller) return res.status(404).json({ message: "Seller not found" });

    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Product not found" });

    // Check ownership using seller._id
    if (!product.sellerId.equals(seller._id)) {
      return res.status(403).json({ message: "You cannot update this product" });
    }

    const {
      brand = product.brand,
      model = product.model,
      productType = product.productType,
      color = product.color,
      storage = product.storage,
      ram = product.ram,
      price = product.price
    } = req.body;

    product.brand = brand;
    product.model = model;
    product.productType = productType;
    product.color = color;
    product.storage = storage;
    product.ram = ram;
    product.price = price;

    if (req.file) product.image = req.file.path;

    await product.save();
    res.json({ message: "Product updated successfully", product });
  } catch (err) {
    console.error("UPDATE PRODUCT ERROR:", err);
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

    const seller = await Seller.findOne({ userId: user._id });
    if (!seller) return res.status(404).json({ message: "Seller not found" });

    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Product not found" });

    // Check ownership
    if (!product.sellerId.equals(seller._id)) {
      return res.status(403).json({ message: "You cannot delete this product" });
    }

    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: "Product deleted successfully" });
  } catch (err) {
    console.error("DELETE PRODUCT ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});




// ====== DB CONNECT ======
mongoose.connect(process.env.MONGO_URI).then(() => {
  console.log("MongoDB connected");
}).catch(err => console.log(err));

app.listen(process.env.PORT, () => console.log(`Server running on ${process.env.PORT}`));