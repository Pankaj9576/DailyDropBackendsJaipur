const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const User = require('../models/User');
const Order = require('../models/Order');
const Inventory = require('../models/Inventory');
const Product = require('../models/Product');

// Signup Endpoint (for customers)
router.post('/auth/register', async (req, res) => {
  const { name, email, phone, password, address, pincode, building } = req.body;

  // Validate pincode (Jaipur pincodes: 302001 to 302039)
  const pincodeNum = parseInt(pincode);
  if (!pincode || pincodeNum < 302001 || pincodeNum > 302039) {
    return res.status(400).json({ error: 'We do not deliver to this pincode yet' });
  }

  try {
    const bcrypt = require('bcryptjs');
    const jwt = require('jsonwebtoken');
    const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
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

// Login Endpoint
router.post('/auth/login', async (req, res) => {
  const { email, password, role } = req.body;

  try {
    const bcrypt = require('bcryptjs');
    const jwt = require('jsonwebtoken');
    const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
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
router.get('/auth/verify', authenticateToken, async (req, res) => {
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

// Update Profile Endpoint (allows customer to update email and password)
router.put('/auth/profile', authenticateToken, async (req, res) => {
  const { name, phone, address, building, pincode, email, password } = req.body;

  console.log('Profile update request received:', { userId: req.user.userId, payload: req.body });

  try {
    const bcrypt = require('bcryptjs');
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

// Create Order Endpoint with Stock Check
router.post('/orders', authenticateToken, async (req, res) => {
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

// Get Orders for Customer (only their own orders)
router.get('/orders', authenticateToken, async (req, res) => {
  try {
    const { date } = req.query;
    let query = { userId: req.user.userId };

    // Filter by date (ignoring time)
    if (date) {
      const startDate = new Date(date);
      startDate.setHours(0, 0, 0, 0);
      const endDate = new Date(date);
      endDate.setHours(23, 59, 59, 999);
      query.createdAt = { $gte: startDate, $lte: endDate };
    }

    const orders = await Order.find(query).populate('userId', 'name email').sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    console.error('Fetch orders error:', err);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

module.exports = router;