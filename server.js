const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Atlas Connection
const mongoURI = 'mongodb+srv://pankajut7809:C7Sh121M59unx5QI@milkcluster.vsj7iks.mongodb.net/dailydrop?retryWrites=true&w=majority';
mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch((err) => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['customer', 'admin', 'packer', 'delivery'], required: true },
  address: { type: String },
  pincode: { type: String },
  building: { type: String },
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model('User', userSchema);

// Product Schema
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  unit: { type: String, required: true },
  emoji: { type: String },
  createdAt: { type: Date, default: Date.now },
});
const Product = mongoose.model('Product', productSchema);

// Inventory Schema
const inventorySchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  quantity: { type: Number, required: true, min: 0 },
  unit: { type: String, required: true },
  addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now },
});
const Inventory = mongoose.model('Inventory', inventorySchema);

// Order Schema
const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    name: String,
    quantity: Number,
    price: Number,
  }],
  total: { type: Number, required: true },
  address: { type: String, required: true },
  status: { type: String, enum: ['pending', 'packed', 'out_for_delivery', 'delivered'], default: 'pending' },
  priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  createdAt: { type: Date, default: Date.now },
});
const Order = mongoose.model('Order', orderSchema);

// Initialize Default Admin
const initializeAdmin = async () => {
  try {
    const adminExists = await User.findOne({ email: 'admin@gmail.com', role: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('Dimple#@123', 10);
      const admin = new User({
        name: 'Admin',
        email: 'admin@gmail.com',
        phone: '0000000000',
        password: hashedPassword,
        role: 'admin',
      });
      await admin.save();
      console.log('Default admin created with email: admin@gmail.com');
    } else {
      console.log('Default admin already exists');
    }
  } catch (err) {
    console.error('Error creating default admin:', err);
  }
};
initializeAdmin();

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.log('No token provided in request');
    return res.status(401).json({ error: 'Access denied: No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Token verification failed:', err.message);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    console.log('Token verified, user:', user);
    next();
  });
};

// Middleware to restrict to admin
const restrictToAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    console.log('Access denied: User is not admin, role:', req.user.role);
    return res.status(403).json({ error: 'Access restricted to admins' });
  }
  next();
};

// Signup Endpoint (for customers)
app.post('/api/auth/register', async (req, res) => {
  const { name, email, phone, password, address, pincode, building } = req.body;

  // Validate pincode (Jaipur pincodes: 302001 to 302039)
  const pincodeNum = parseInt(pincode);
  if (!pincode || pincodeNum < 302001 || pincodeNum > 302039) {
    return res.status(400).json({ error: 'We do not deliver to this pincode yet' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email,
      phone,
      password: hashedPassword,
      role: 'customer',
      address,
      pincode,
      building,
    });
    await user.save();

    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token, user: { id: user._id, name, email, role: user.role, address, pincode, building } });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Staff Registration Endpoint (for admin to register packers/delivery)
app.post('/api/auth/register-staff', authenticateToken, restrictToAdmin, async (req, res) => {
  const { name, email, phone, password, role } = req.body;

  if (!['packer', 'delivery'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role. Must be packer or delivery' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
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
    console.error('Staff registration error:', err);
    res.status(500).json({ error: 'Staff registration failed' });
  }
});

// Login Endpoint
app.post('/api/auth/login', async (req, res) => {
  const { email, password, role } = req.body;

  try {
    const user = await User.findOne({ email, role });
    if (!user) {
      console.log(`Login failed: No user found with email ${email} and role ${role}`);
      return res.status(400).json({ error: 'Invalid email or role' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log(`Login failed: Invalid password for email ${email}`);
      return res.status(400).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    console.log(`Login successful for user: ${email}`);
    res.json({ token, user: { id: user._id, name: user.name, email, role: user.role, address: user.address, pincode: user.pincode, building: user.building } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Verify Token Endpoint
app.get('/api/auth/verify', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      console.log(`Verify failed: User not found for ID ${req.user.userId}`);
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user: { id: user._id, name: user.name, email: user.email, role: user.role, address: user.address, pincode: user.pincode, building: user.building } });
  } catch (err) {
    console.error('Verification error:', err);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Update Profile Endpoint (allows admin to update email and password)
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  const { name, phone, address, building, pincode, email, password } = req.body;

  console.log('Profile update request received:', { userId: req.user.userId, payload: req.body });

  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      console.log(`User not found for ID: ${req.user.userId}`);
      return res.status(404).json({ error: 'User not found' });
    }

    if (email && email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        console.log(`Email already in use: ${email}`);
        return res.status(400).json({ error: 'Email already in use' });
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

    await user.save();
    console.log(`Profile updated successfully for user: ${user.email}`);

    res.json({ user: { id: user._id, name: user.name, email: user.email, role: user.role, address: user.address, pincode: user.pincode, building: user.building } });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).json({ error: 'Profile update failed' });
  }
});

// Get Users Endpoint (for admin, with role filter and search)
app.get('/api/users', authenticateToken, restrictToAdmin, async (req, res) => {
  try {
    const { role, search } = req.query;
    let query = {};
    if (role) {
      query.role = { $in: role.split(',').map(r => r.trim()) };
    }
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
      ];
    }
    const users = await User.find(query).sort({ createdAt: -1 });
    res.json(users.map(user => ({
      id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      role: user.role,
      address: user.address,
      pincode: user.pincode,
      building: user.building,
      createdAt: user.createdAt,
    })));
    console.log(`Fetched users with role filter: ${role || 'all'}, search: ${search || 'none'}`);
  } catch (err) {
    console.error('Fetch users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Update User Endpoint (for admin)
app.put('/api/users/:id', authenticateToken, restrictToAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, email, phone, address, pincode, building, role } = req.body;

  console.log('User update request received:', { userId: id, payload: req.body });

  try {
    const user = await User.findById(id);
    if (!user) {
      console.log(`User not found for ID: ${id}`);
      return res.status(404).json({ error: 'User not found' });
    }

    // Validate pincode (Jaipur pincodes: 302001 to 302039)
    if (pincode) {
      const pincodeNum = parseInt(pincode);
      if (pincodeNum < 302001 || pincodeNum > 302039) {
        return res.status(400).json({ error: 'Invalid pincode for Jaipur' });
      }
    }

    // Validate role
    if (role && !['customer', 'admin', 'packer', 'delivery'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    // Check email uniqueness
    if (email && email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        console.log(`Email already in use: ${email}`);
        return res.status(400).json({ error: 'Email already in use' });
      }
      user.email = email;
    }

    user.name = name || user.name;
    user.phone = phone || user.phone;
    user.address = address || user.address;
    user.building = building || user.building;
    user.pincode = pincode || user.pincode;
    user.role = role || user.role;

    await user.save();
    console.log(`User updated successfully: ${user.email}`);

    res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      role: user.role,
      address: user.address,
      pincode: user.pincode,
      building: user.building,
    });
  } catch (err) {
    console.error('User update error:', err);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Delete User Endpoint (for admin)
app.delete('/api/users/:id', authenticateToken, restrictToAdmin, async (req, res) => {
  const { id } = req.params;

  console.log('User delete request received:', { userId: id });

  try {
    // Prevent admin from deleting themselves
    if (id === req.user.userId) {
      console.log('Cannot delete self: ', req.user.userId);
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }

    const user = await User.findByIdAndDelete(id);
    if (!user) {
      console.log(`User not found for ID: ${id}`);
      return res.status(404).json({ error: 'User not found' });
    }

    console.log(`User deleted successfully: ${user.email}`);
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error('User delete error:', err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Product CRUD Endpoints
app.get('/api/products', async (req, res) => {
  try {
    const { search } = req.query;
    let query = {};
    if (search) {
      query = { name: { $regex: search, $options: 'i' } };
    }
    const products = await Product.find(query).sort({ createdAt: -1 });
    res.json(products);
  } catch (err) {
    console.error('Fetch products error:', err);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

app.post('/api/products', authenticateToken, restrictToAdmin, async (req, res) => {
  const { name, price, unit, emoji } = req.body;

  try {
    const product = new Product({ name, price, unit, emoji });
    await product.save();
    res.status(201).json(product);
  } catch (err) {
    console.error('Create product error:', err);
    res.status(500).json({ error: 'Failed to create product' });
  }
});

app.put('/api/products/:id', authenticateToken, restrictToAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, price, unit, emoji } = req.body;

  try {
    const product = await Product.findByIdAndUpdate(id, { name, price, unit, emoji }, { new: true });
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json(product);
  } catch (err) {
    console.error('Update product error:', err);
    res.status(500).json({ error: 'Failed to update product' });
  }
});

app.delete('/api/products/:id', authenticateToken, restrictToAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const product = await Product.findByIdAndDelete(id);
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json({ message: 'Product deleted' });
  } catch (err) {
    console.error('Delete product error:', err);
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

// Inventory Endpoints
app.post('/api/inventory', authenticateToken, restrictToAdmin, async (req, res) => {
  const { productId, quantity, unit } = req.body;

  try {
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
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
    console.error('Create inventory error:', err);
    res.status(500).json({ error: 'Failed to create inventory entry' });
  }
});

app.get('/api/inventory', authenticateToken, restrictToAdmin, async (req, res) => {
  try {
    const { search } = req.query;
    let inventoryQuery = {};
    if (search) {
      const products = await Product.find({ name: { $regex: search, $options: 'i' } }).select('_id');
      const productIds = products.map(p => p._id);
      inventoryQuery = { productId: { $in: productIds } };
    }
    const inventory = await Inventory.find(inventoryQuery)
      .populate('productId', 'name emoji')
      .populate('addedBy', 'name')
      .sort({ createdAt: -1 });

    // Aggregate total quantity per product
    const aggregatedInventory = await Inventory.aggregate([
      { $match: inventoryQuery },
      {
        $group: {
          _id: '$productId',
          totalQuantity: { $sum: '$quantity' },
          unit: { $first: '$unit' },
        },
      },
      {
        $lookup: {
          from: 'products',
          localField: '_id',
          foreignField: '_id',
          as: 'product',
        },
      },
      { $unwind: '$product' },
      {
        $project: {
          productId: '$_id',
          name: '$product.name',
          emoji: '$product.emoji',
          totalQuantity: 1,
          unit: 1,
        },
      },
      { $sort: { 'product.createdAt': -1 } },
    ]);

    res.json({ inventory, aggregatedInventory });
  } catch (err) {
    console.error('Fetch inventory error:', err);
    res.status(500).json({ error: 'Failed to fetch inventory' });
  }
});

app.put('/api/inventory/:id', authenticateToken, restrictToAdmin, async (req, res) => {
  const { id } = req.params;
  const { quantity, unit } = req.body;

  try {
    const inventory = await Inventory.findByIdAndUpdate(id, { quantity, unit }, { new: true });
    if (!inventory) return res.status(404).json({ error: 'Inventory entry not found' });
    res.json(inventory);
  } catch (err) {
    console.error('Update inventory error:', err);
    res.status(500).json({ error: 'Failed to update inventory' });
  }
});

// Get Orders Endpoint with Date, Status, and Search Filter
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { date, status, search } = req.query;
    let query = {};

    // Filter by date (ignoring time)
    if (date) {
      const startDate = new Date(date);
      startDate.setHours(0, 0, 0, 0);
      const endDate = new Date(date);
      endDate.setHours(23, 59, 59, 999);
      query.createdAt = { $gte: startDate, $lte: endDate };
    }

    // Filter by status
    if (status && status !== 'all') {
      query.status = status;
    }

    // Filter by search (customer name or email)
    if (search) {
      const users = await User.find({
        $or: [
          { name: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } },
        ],
      }).select('_id');
      const userIds = users.map(u => u._id);
      query.userId = { $in: userIds };
    }

    const orders = await Order.find(query).populate('userId', 'name email').sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    console.error('Fetch orders error:', err);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Create Order Endpoint with Stock Check
app.post('/api/orders', authenticateToken, async (req, res) => {
  const { items, total, address } = req.body;

  try {
    // Check stock availability
    for (const item of items) {
      const inventory = await Inventory.aggregate([
        { $match: { productId: new mongoose.Types.ObjectId(item.productId) } },
        { $group: { _id: '$productId', totalQuantity: { $sum: '$quantity' } } },
      ]);
      const availableStock = inventory.length > 0 ? inventory[0].totalQuantity : 0;
      if (availableStock < item.quantity) {
        const product = await Product.findById(item.productId);
        return res.status(400).json({ error: `Insufficient stock for ${product.name}. Available: ${availableStock} ${product.unit}` });
      }
    }

    // Create order
    const order = new Order({
      userId: req.user.userId,
      items,
      total,
      address,
    });
    await order.save();

    // Deduct stock
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

    res.status(201).json(order);
  } catch (err) {
    console.error('Create order error:', err);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// Update Order Status Endpoint with Stock Check
app.put('/api/orders/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  try {
    const order = await Order.findById(id);
    if (!order) return res.status(404).json({ error: 'Order not found' });

    // If updating to 'packed', ensure stock is still available
    if (status === 'packed') {
      for (const item of order.items) {
        const inventory = await Inventory.aggregate([
          { $match: { productId: new mongoose.Types.ObjectId(item.productId) } },
          { $group: { _id: '$productId', totalQuantity: { $sum: '$quantity' } } },
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
    res.json(order);
  } catch (err) {
    console.error('Update order status error:', err);
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});