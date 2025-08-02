const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const http = require("http");
const { Server } = require("socket.io");
const multer = require("multer");
require("dotenv").config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";

// Multer Configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // Directory to store uploaded files
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname); // Unique filename
  },
});
const upload = multer({ storage: storage });

// Middleware
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static("uploads")); // Serve uploaded files statically

// MongoDB Atlas Connection
const mongoURI = "mongodb+srv://pankajut7809:C7Sh121M59unx5QI@milkcluster.vsj7iks.mongodb.net/dailydrop?retryWrites=true&w=majority";
mongoose
  .connect(mongoURI, {
    serverSelectionTimeoutMS: 5000,
  })
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

mongoose.connection.on("disconnected", () => console.log("MongoDB disconnected"));
mongoose.connection.on("error", (err) => console.error("MongoDB connection error:", err));

// Contact Schema
const contactSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
const Contact = mongoose.model("Contact", contactSchema);

// Shop Schema
const shopSchema = new mongoose.Schema({
  location: {
    type: {
      type: String,
      enum: ["Point"],
      required: true,
      default: "Point",
    },
    coordinates: {
      type: [Number], // [longitude, latitude]
      required: true,
    },
  },
  updatedAt: { type: Date, default: Date.now },
});
shopSchema.index({ location: "2dsphere" });
const Shop = mongoose.model("Shop", shopSchema);

// Product Schema
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  unit: { type: String, required: true },
  images: [{ type: String, required: true }],
  createdAt: { type: Date, default: Date.now },
});
const Product = mongoose.model("Product", productSchema);

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["customer", "admin", "packer", "delivery"], required: true },
  address: { type: String },
  pincode: { type: String },
  building: { type: String },
  location: {
    type: {
      type: String,
      enum: ["Point"],
      default: "Point",
    },
    coordinates: [Number],
  },
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model("User", userSchema);

// Inventory Schema
const inventorySchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
  quantity: { type: Number, required: true, min: 0 },
  unit: { type: String, required: true },
  addedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  createdAt: { type: Date, default: Date.now },
});
const Inventory = mongoose.model("Inventory", inventorySchema);

// Order Schema
const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  items: [
    {
      productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
      name: String,
      quantity: Number,
      price: Number,
    },
  ],
  total: { type: Number, required: true },
  address: { type: String, required: true },
  status: { type: String, enum: ["pending", "packed", "out_for_delivery", "delivered"], default: "pending" },
  priority: { type: String, enum: ["low", "medium", "high"], default: "medium" },
  createdAt: { type: Date, default: Date.now },
});
const Order = mongoose.model("Order", orderSchema);

// Notification Schema
const notificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  orderId: { type: mongoose.Schema.Types.ObjectId, ref: "Order", required: true },
  message: { type: String, required: true },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});
const Notification = mongoose.model("Notification", notificationSchema);

// Complaint Schema
const complaintSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  orderId: { type: mongoose.Schema.Types.ObjectId, ref: "Order", default: null },
  description: { type: String, required: true },
  status: { type: String, enum: ["pending", "resolved"], default: "pending" },
  createdAt: { type: Date, default: Date.now },
});
const Complaint = mongoose.model("Complaint", complaintSchema);

// Contact Endpoint
app.post("/api/contact", async (req, res) => {
  try {
    const { name, email, message } = req.body;
    if (!name || !email || !message) {
      return res.status(400).json({ error: "All fields are required" });
    }
    if (message.length < 10) {
      return res.status(400).json({ error: "Message must be at least 10 characters" });
    }
    const contact = new Contact({ name, email, message });
    await contact.save();
    res.status(201).json({ message: "Message sent successfully" });
  } catch (err) {
    console.error("Contact submission error:", err);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// Initialize Default Admin
const initializeAdmin = async () => {
  try {
    const adminExists = await User.findOne({ email: "admin@example.com", role: "admin" });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash("Dimple#@123", 10);
      const admin = new User({
        name: "Admin",
        email: "admin@example.com",
        phone: "0000000000",
        password: hashedPassword,
        role: "admin",
      });
      await admin.save();
      console.log("Default admin created with email: admin@example.com");
    } else {
      console.log("Default admin already exists");
    }
  } catch (err) {
    console.error("Error creating default admin:", err);
  }
};
initializeAdmin();

// Socket.IO Connection
io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);

  socket.on("joinRoom", (userId) => {
    socket.join(userId);
    console.log(`User ${userId} joined room`);
  });

  socket.on("disconnect", () => {
    console.log("Client disconnected:", socket.id);
  });
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Access denied: No token provided" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
};

const restrictToAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access restricted to admins" });
  }
  next();
};

const restrictToRoles = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ error: `Access restricted to ${roles.join(" or ")}` });
  }
  next();
};

// Signup Endpoint (for customers)
app.post("/api/auth/register", async (req, res) => {
  const { name, email, phone, password, address, pincode, building, location } = req.body;

  const pincodeNum = parseInt(pincode);
  if (!pincode || pincodeNum < 302001 || pincodeNum > 302039) {
    return res.status(400).json({ error: "We do not deliver to this pincode yet" });
  }

  const shop = await Shop.findOne();
  if (!shop) {
    return res.status(500).json({ error: "Shop location not set by admin" });
  }

  const userLocation = location && Array.isArray(location) && location.length === 2 ? location : null;
  if (!userLocation) {
    return res.status(400).json({ error: "Invalid location format. Provide [latitude, longitude]" });
  }

  const R = 6371;
  const [userLat, userLng] = userLocation;
  const [shopLat, shopLng] = shop.location.coordinates;
  const dLat = (userLat - shopLat) * Math.PI / 180;
  const dLng = (userLng - shopLng) * Math.PI / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(shopLat * Math.PI / 180) * Math.cos(userLat * Math.PI / 180) * Math.sin(dLng / 2) * Math.sin(dLng / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  const distance = R * c;

  if (distance > 3) {
    return res.status(400).json({ error: "User location must be within 3km of the shop" });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email,
      phone,
      password: hashedPassword,
      role: "customer",
      address,
      pincode,
      building,
      location: {
        type: "Point",
        coordinates: userLocation,
      },
    });
    await user.save();

    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, { expiresIn: "1h" });
    res.status(201).json({
      token,
      user: { id: user._id, name, email, role: user.role, address, pincode, building, location: userLocation },
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// Staff Registration Endpoint
app.post("/api/auth/register-staff", authenticateToken, restrictToAdmin, async (req, res) => {
  const { name, email, phone, password, role } = req.body;

  if (!["packer", "delivery"].includes(role)) {
    return res.status(400).json({ error: "Invalid role. Must be packer or delivery" });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email,
      phone,
      password: hashedPassword,
      role,
    });
    await user.save();

    res.status(201).json({ user: { id: user._id, name, email, role } });
  } catch (err) {
    console.error("Staff registration error:", err);
    res.status(500).json({ error: "Staff registration failed" });
  }
});

// Login Endpoint
app.post("/api/auth/login", async (req, res) => {
  const { email, password, role } = req.body;

  try {
    const user = await User.findOne({ email, role });
    if (!user) {
      return res.status(400).json({ error: "Invalid email or role" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid password" });
    }

    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, { expiresIn: "1h" });
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email,
        role: user.role,
        address: user.address,
        pincode: user.pincode,
        building: user.building,
        location: user.location?.coordinates,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Verify Token Endpoint
app.get("/api/auth/verify", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        address: user.address,
        pincode: user.pincode,
        building: user.building,
        location: user.location?.coordinates,
      },
    });
  } catch (err) {
    console.error("Verification error:", err);
    res.status(500).json({ error: "Verification failed" });
  }
});

// Update Profile Endpoint
app.put("/api/auth/profile", authenticateToken, async (req, res) => {
  const { name, phone, address, building, pincode, email, password, location } = req.body;

  console.log("Profile update request received:", { userId: req.user.userId, payload: req.body });

  const updatableFields = { name, phone, address, building, pincode, email, password, location };
  const hasUpdatableField = Object.values(updatableFields).some(
    (field) => field !== undefined && field !== null && (typeof field !== "object" || Object.keys(field).length > 0)
  );
  if (!hasUpdatableField) {
    return res.status(400).json({ error: "No updatable fields provided" });
  }

  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (email && email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: "Email already in use" });
      }
      user.email = email;
    }

    if (password) {
      user.password = await bcrypt.hash(password, 10);
    }

    user.name = name || user.name;
    user.phone = phone || user.phone;
    user.address = address || user.address;
    user.building = building || user.building;
    user.pincode = pincode || user.pincode;

    if (location && Array.isArray(location) && location.length === 2) {
      const shop = await Shop.findOne();
      if (!shop) {
        return res.status(500).json({ error: "Shop location not set by admin" });
      }

      const R = 6371;
      const [userLat, userLng] = location;
      const [shopLat, shopLng] = shop.location.coordinates;
      const dLat = (userLat - shopLat) * Math.PI / 180;
      const dLng = (userLng - shopLng) * Math.PI / 180;
      const a =
        Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(shopLat * Math.PI / 180) * Math.cos(userLat * Math.PI / 180) * Math.sin(dLng / 2) * Math.sin(dLng / 2);
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
      const distance = R * c;

      if (distance > 3) {
        return res.status(400).json({ error: "New location must be within 3km of the shop" });
      }

      user.location = { type: "Point", coordinates: location };
    }

    await user.save();
    console.log(`Profile updated successfully for user: ${user.email}`);

    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        address: user.address,
        pincode: user.pincode,
        building: user.building,
        location: user.location?.coordinates,
      },
    });
  } catch (err) {
    console.error("Profile update error:", err);
    res.status(500).json({ error: "Profile update failed" });
  }
});

// Get Users Endpoint
app.get("/api/users", authenticateToken, restrictToAdmin, async (req, res) => {
  try {
    const { role, search } = req.query;
    let query = {};
    if (role) {
      query.role = { $in: role.split(",").map((r) => r.trim()) };
    }
    if (search) {
      query.$or = [{ name: { $regex: search, $options: "i" } }, { email: { $regex: search, $options: "i" } }];
    }
    const users = await User.find(query).sort({ createdAt: -1 });
    res.json(
      users.map((user) => ({
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        address: user.address,
        pincode: user.pincode,
        building: user.building,
        location: user.location?.coordinates,
        createdAt: user.createdAt,
      }))
    );
  } catch (err) {
    console.error("Fetch users error:", err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

// Update User Endpoint
app.put("/api/users/:id", authenticateToken, restrictToAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, email, phone, address, pincode, building, role, location } = req.body;

  console.log("User update request received:", { userId: id, payload: req.body });

  try {
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (pincode) {
      const pincodeNum = parseInt(pincode);
      if (pincodeNum < 302001 || pincodeNum > 302039) {
        return res.status(400).json({ error: "Invalid pincode for Jaipur" });
      }
    }

    if (role && !["customer", "admin", "packer", "delivery"].includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    if (email && email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: "Email already in use" });
      }
      user.email = email;
    }

    user.name = name || user.name;
    user.phone = phone || user.phone;
    user.address = address || user.address;
    user.building = building || user.building;
    user.pincode = pincode || user.pincode;
    user.role = role || user.role;

    if (location && Array.isArray(location) && location.length === 2) {
      const shop = await Shop.findOne();
      if (!shop) {
        return res.status(500).json({ error: "Shop location not set by admin" });
      }

      const R = 6371;
      const [userLat, userLng] = location;
      const [shopLat, shopLng] = shop.location.coordinates;
      const dLat = (userLat - shopLat) * Math.PI / 180;
      const dLng = (userLng - shopLng) * Math.PI / 180;
      const a =
        Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(shopLat * Math.PI / 180) * Math.cos(userLat * Math.PI / 180) * Math.sin(dLng / 2) * Math.sin(dLng / 2);
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
      const distance = R * c;

      if (distance > 3) {
        return res.status(400).json({ error: "New location must be within 3km of the shop" });
      }

      user.location = { type: "Point", coordinates: location };
    }

    await user.save();
    res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      role: user.role,
      address: user.address,
      pincode: user.pincode,
      building: user.building,
      location: user.location?.coordinates,
    });
  } catch (err) {
    console.error("User update error:", err);
    res.status(500).json({ error: "Failed to update user" });
  }
});

// Delete User Endpoint
app.delete("/api/users/:id", authenticateToken, restrictToAdmin, async (req, res) => {
  const { id } = req.params;

  console.log("User delete request received:", { userId: id });

  try {
    if (id === req.user.userId) {
      return res.status(400).json({ error: "Cannot delete your own account" });
    }

    const user = await User.findByIdAndDelete(id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error("User delete error:", err);
    res.status(500).json({ error: "Failed to delete user" });
  }
});

// Product CRUD Endpoints
app.get("/api/products", async (req, res) => {
  try {
    const { search } = req.query;
    let query = {};
    if (search) {
      query = { name: { $regex: search, $options: "i" } };
    }
    const products = await Product.find(query).sort({ createdAt: -1 });
    res.json(products);
  } catch (err) {
    console.error("Fetch products error:", err);
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

app.post("/api/products", authenticateToken, restrictToAdmin, upload.array("images", 5), async (req, res) => {
  const { name, price, unit } = req.body;
  const images = req.files ? req.files.map((file) => file.path) : [];

  if (!name || !price || !unit) {
    return res.status(400).json({ error: "Name, price, and unit are required" });
  }
  if (images.length < 2) {
    return res.status(400).json({ error: "Please upload at least 2 images" });
  }

  try {
    const product = new Product({ name, price, unit, images });
    await product.save();
    res.status(201).json(product);
  } catch (err) {
    console.error("Create product error:", err);
    res.status(500).json({ error: "Failed to create product" });
  }
});

app.put("/api/products/:id", authenticateToken, restrictToAdmin, upload.array("images", 5), async (req, res) => {
  const { id } = req.params;
  const { name, price, unit } = req.body;
  const images = req.files ? req.files.map((file) => file.path) : [];

  if (!name || !price || !unit) {
    return res.status(400).json({ error: "Name, price, and unit are required" });
  }
  if (images.length < 2 && !req.body.images) {
    return res.status(400).json({ error: "Please upload at least 2 images" });
  }

  try {
    const updateData = { name, price, unit };
    if (images.length > 0) {
      updateData.images = images;
    } else if (req.body.images) {
      updateData.images = req.body.images;
    }

    const product = await Product.findByIdAndUpdate(id, updateData, { new: true });
    if (!product) return res.status(404).json({ error: "Product not found" });
    res.json(product);
  } catch (err) {
    console.error("Update product error:", err);
    res.status(500).json({ error: "Failed to update product" });
  }
});

app.delete("/api/products/:id", authenticateToken, restrictToAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const product = await Product.findByIdAndDelete(id);
    if (!product) return res.status(404).json({ error: "Product not found" });
    res.json({ message: "Product deleted" });
  } catch (err) {
    console.error("Delete product error:", err);
    res.status(500).json({ error: "Failed to delete product" });
  }
});

// Inventory Endpoints
app.post("/api/inventory", authenticateToken, restrictToAdmin, async (req, res) => {
  const { productId, quantity, unit } = req.body;

  try {
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }

    const inventory = new Inventory({
      productId,
      quantity,
      unit,
      addedBy: req.user.userId,
    });
    await inventory.save();
    res.status(201).json(inventory);
  } catch (err) {
    console.error("Create inventory error:", err);
    res.status(500).json({ error: "Failed to create inventory entry" });
  }
});

app.get("/api/inventory", authenticateToken, restrictToAdmin, async (req, res) => {
  try {
    const { search } = req.query;
    let inventoryQuery = {};
    if (search) {
      const products = await Product.find({ name: { $regex: search, $options: "i" } }).select("_id");
      const productIds = products.map((p) => p._id);
      inventoryQuery = { productId: { $in: productIds } };
    }
    const inventory = await Inventory.find(inventoryQuery)
      .populate("productId", "name images")
      .populate("addedBy", "name")
      .sort({ createdAt: -1 });

    const aggregatedInventory = await Inventory.aggregate([
      { $match: inventoryQuery },
      {
        $group: {
          _id: "$productId",
          totalQuantity: { $sum: "$quantity" },
          unit: { $first: "$unit" },
        },
      },
      {
        $lookup: {
          from: "products",
          localField: "_id",
          foreignField: "_id",
          as: "product",
        },
      },
      { $unwind: { path: "$product", preserveNullAndEmptyArrays: true } },
      {
        $project: {
          productId: "$_id",
          name: { $ifNull: ["$product.name", "Unknown Product"] },
          images: { $ifNull: ["$product.images", []] },
          totalQuantity: 1,
          unit: 1,
        },
      },
      { $sort: { "product.createdAt": -1 } },
    ]);

    res.json({ inventory, aggregatedInventory });
  } catch (err) {
    console.error("Fetch inventory error:", err);
    res.status(500).json({ error: "Failed to fetch inventory" });
  }
});

app.put("/api/inventory/:id", authenticateToken, restrictToAdmin, async (req, res) => {
  const { id } = req.params;
  const { quantity, unit } = req.body;

  try {
    const inventory = await Inventory.findByIdAndUpdate(id, { quantity, unit }, { new: true });
    if (!inventory) return res.status(404).json({ error: "Inventory entry not found" });
    res.json(inventory);
  } catch (err) {
    console.error("Update inventory error:", err);
    res.status(500).json({ error: "Failed to update inventory" });
  }
});

// Get Orders Endpoint
app.get("/api/orders", authenticateToken, async (req, res) => {
  try {
    const { date, status, search } = req.query;
    let query = {};

    if (req.user.role === "customer") {
      query.userId = new mongoose.Types.ObjectId(req.user.userId);
    } else if (req.user.role === "packer") {
      query.status = { $in: ["pending", "packed"] };
    } else if (req.user.role === "delivery") {
      query.status = { $in: ["packed", "out_for_delivery", "delivered"] };
    }

    if (date) {
      const startDate = new Date(date);
      startDate.setHours(0, 0, 0, 0);
      const endDate = new Date(date);
      endDate.setHours(23, 59, 59, 999);
      query.createdAt = { $gte: startDate, $lte: endDate };
    } else {
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      const tomorrow = new Date(today);
      tomorrow.setDate(tomorrow.getDate() + 1);
      query.createdAt = { $gte: today, $lte: tomorrow };
    }

    if (status && status !== "all" && req.user.role === "admin") {
      query.status = status;
    }

    if (search && req.user.role === "admin") {
      const users = await User.find({
        $or: [{ name: { $regex: search, $options: "i" } }, { email: { $regex: search, $options: "i" } }],
      }).select("_id");
      const userIds = users.map((u) => u._id);
      query.userId = { $in: userIds };
    }

    const orders = await Order.find(query)
      .populate("userId", "name email phone address pincode building location")
      .populate("items.productId", "name images")
      .sort({ createdAt: -1 });

    res.json(orders);
  } catch (err) {
    console.error("Fetch orders error:", err);
    res.status(500).json({ error: "Failed to fetch orders" });
  }
});

// Create Order Endpoint
app.post("/api/orders", authenticateToken, restrictToRoles(["customer"]), async (req, res) => {
  const { items, total, address } = req.body;

  try {
    for (const item of items) {
      const inventory = await Inventory.aggregate([
        { $match: { productId: new mongoose.Types.ObjectId(item.productId) } },
        { $group: { _id: "$productId", totalQuantity: { $sum: "$quantity" } } },
      ]);
      const availableStock = inventory.length > 0 ? inventory[0].totalQuantity : 0;
      if (availableStock < item.quantity) {
        const product = await Product.findById(item.productId);
        return res.status(400).json({ error: `Insufficient stock for ${product.name}. Available: ${availableStock} ${product.unit}` });
      }
    }

    const order = new Order({
      userId: req.user.userId,
      items,
      total,
      address,
    });
    await order.save();

    for (const item of items) {
      const inventoryEntries = await Inventory.find({ productId: item.productId }).sort({ createdAt: 1 });
      let remainingQuantity = item.quantity;
      for (const entry of inventoryEntries) {
        if (remainingQuantity <= 0) break;
        if (entry.quantity >= remainingQuantity) {
          entry.quantity -= remainingQuantity;
          await entry.save();
          remainingQuantity = 0;
        } else {
          remainingQuantity -= entry.quantity;
          entry.quantity = 0;
          await entry.save();
        }
      }
    }

    const populatedOrder = await Order.findById(order._id)
      .populate("userId", "name email phone address pincode building location")
      .populate("items.productId", "name images");
    io.emit("orderCreated", populatedOrder);
    io.to(order.userId.toString()).emit("notification", {
      orderId: order._id,
      message: "Your order has been placed successfully!",
    });

    res.status(201).json(populatedOrder);
  } catch (err) {
    console.error("Create order error:", err);
    res.status(500).json({ error: "Failed to create order" });
  }
});

// Update Order Status Endpoint
app.put("/api/orders/:id", authenticateToken, restrictToRoles(["packer", "delivery", "admin"]), async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  try {
    const order = await Order.findById(id)
      .populate("userId", "name email phone address pincode building location")
      .populate("items.productId", "name images");
    if (!order) return res.status(404).json({ error: "Order not found" });

    if (req.user.role === "packer" && status !== "packed") {
      return res.status(400).json({ error: "Packers can only update status to packed" });
    }
    if (req.user.role === "delivery" && !["out_for_delivery", "delivered"].includes(status)) {
      return res.status(400).json({ error: "Delivery personnel can only update status to out_for_delivery or delivered" });
    }

    if (status === "packed") {
      for (const item of order.items) {
        const inventory = await Inventory.aggregate([
          { $match: { productId: new mongoose.Types.ObjectId(item.productId) } },
          { $group: { _id: "$productId", totalQuantity: { $sum: "$quantity" } } },
        ]);
        const availableStock = inventory.length > 0 ? inventory[0].totalQuantity : 0;
        if (availableStock < item.quantity) {
          const product = await Product.findById(item.productId);
          return res.status(400).json({ error: `Insufficient stock for ${product.name}. Available: ${availableStock} ${product.unit}` });
        }
      }
    }

    order.status = status;
    await order.save();

    let message = "";
    if (status === "packed") {
      message = "Your order has been packed and is ready for delivery!";
      const deliveryUsers = await User.find({ role: "delivery" }).select("_id");
      deliveryUsers.forEach((user) => {
        io.to(user._id.toString()).emit("notification", {
          orderId: order._id,
          message: `New order ${order._id} is packed and ready for delivery.`,
        });
      });
    } else if (status === "out_for_delivery") {
      message = "Your delivery is on the way!";
    } else if (status === "delivered") {
      message = "Your order has been delivered. Thank you for shopping with DailyDrop!";
    }

    if (message) {
      const notification = new Notification({
        userId: order.userId._id,
        orderId: order._id,
        message,
      });
      await notification.save();

      io.to(order.userId.toString()).emit("notification", {
        orderId: order._id,
        message,
      });
    }

    io.emit("orderUpdated", order);

    res.json(order);
  } catch (err) {
    console.error("Update order status error:", err);
    res.status(500).json({ error: "Failed to update order status" });
  }
});

// Get Notifications Endpoint
app.get("/api/notifications", authenticateToken, async (req, res) => {
  try {
    const notifications = await Notification.find({ userId: req.user.userId })
      .sort({ createdAt: -1 })
      .limit(10);
    res.json(notifications);
  } catch (err) {
    console.error("Fetch notifications error:", err);
    res.status(500).json({ error: "Failed to fetch notifications" });
  }
});

// Submit Complaint Endpoint
app.post("/api/complaints", authenticateToken, restrictToRoles(["customer"]), async (req, res) => {
  const { orderId, description } = req.body;

  try {
    if (orderId) {
      const order = await Order.findById(orderId);
      if (!order) {
        return res.status(404).json({ error: "Order not found" });
      }
      if (order.userId.toString() !== req.user.userId) {
        return res.status(403).json({ error: "You can only submit complaints for your own orders" });
      }
    }

    if (!description || description.trim().length < 10) {
      return res.status(400).json({ error: "Description must be at least 10 characters long" });
    }

    const complaint = new Complaint({
      userId: req.user.userId,
      orderId: orderId || null,
      description,
    });
    await complaint.save();

    res.status(201).json(complaint);
  } catch (err) {
    console.error("Submit complaint error:", err);
    res.status(500).json({ error: "Failed to submit complaint" });
  }
});

// Get Complaints Endpoint
app.get("/api/complaints", authenticateToken, async (req, res) => {
  try {
    const { status, search } = req.query;
    let query = {};

    if (req.user.role !== "admin") {
      query.userId = new mongoose.Types.ObjectId(req.user.userId);
    }

    if (status && status !== "all") {
      query.status = status;
    }

    if (search && req.user.role === "admin") {
      const users = await User.find({
        $or: [{ name: { $regex: search, $options: "i" } }, { email: { $regex: search, $options: "i" } }],
      }).select("_id");
      const userIds = users.map((u) => u._id);
      query.userId = { $in: userIds };
    }

    const complaints = await Complaint.find(query)
      .populate("userId", "name email")
      .populate("orderId", "items total status")
      .sort({ createdAt: -1 });

    res.json(complaints);
  } catch (err) {
    console.error("Fetch complaints error:", err);
    res.status(500).json({ error: "Failed to fetch complaints" });
  }
});

// Update Complaint Status Endpoint
app.put("/api/complaints/:id", authenticateToken, restrictToAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  try {
    if (!["pending", "resolved"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    const complaint = await Complaint.findByIdAndUpdate(id, { status }, { new: true })
      .populate("userId", "name email")
      .populate("orderId", "items total status");
    if (!complaint) {
      return res.status(404).json({ error: "Complaint not found" });
    }

    res.json(complaint);
  } catch (err) {
    console.error("Update complaint error:", err);
    res.status(500).json({ error: "Failed to update complaint" });
  }
});

// Set Shop Location Endpoint
app.put("/api/settings/shop-location", authenticateToken, restrictToAdmin, async (req, res) => {
  const { location } = req.body;

  if (!location || !Array.isArray(location) || location.length !== 2) {
    return res.status(400).json({ error: "Invalid location format. Provide [latitude, longitude]" });
  }

  try {
    let shop = await Shop.findOne();
    if (shop) {
      shop.location.coordinates = location;
    } else {
      shop = new Shop({ location: { type: "Point", coordinates: location } });
    }
    await shop.save();
    res.json({ message: "Shop location updated successfully", location: shop.location.coordinates });
  } catch (err) {
    console.error("Shop location update error:", err);
    res.status(500).json({ error: "Failed to update shop location" });
  }
});

// Seed Products (run once, then comment out)
const seedProducts = async () => {
  const products = [
    {
      name: "Fresh Cow Milk",
      price: 60,
      unit: "liter",
      images: ["uploads/cow-milk-1.jpg", "uploads/cow-milk-2.jpg"],
    },
    {
      name: "Organic Curd",
      price: 40,
      unit: "kg",
      images: ["uploads/curd-1.jpg", "uploads/curd-2.jpg"],
    },
    {
      name: "Pure Ghee",
      price: 500,
      unit: "kg",
      images: ["uploads/ghee-1.jpg", "uploads/ghee-2.jpg"],
    },
  ];
  try {
    await Product.deleteMany();
    await Product.insertMany(products);
    console.log("Products seeded successfully");
  } catch (err) {
    console.error("Error seeding products:", err);
  }
};
seedProducts();

app.use((req, res, next) => {
  console.log(`Route not found: ${req.method} ${req.url}`);
  res.status(404).json({ error: "Route not found" });
});

app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({ error: "Internal server error" });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
