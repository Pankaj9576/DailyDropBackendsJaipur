const express = require('express');
const router = express.Router();
const { authenticateToken, restrictToAdmin } = require('../middleware/auth');
const User = require('../models/User');
const Product = require('../models/Product');
const Inventory = require('../models/Inventory');

// Staff Registration Endpoint (for admin to register packers/delivery)
router.post('/auth/register-staff', authenticateToken, restrictToAdmin, async (req, res) => {
  const { name, email, phone, password, role } = req.body;

  if (!['packer', 'delivery'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role. Must be packer or delivery' });
  }

  try {
    const bcrypt = require('bcryptjs');
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

// Get Users Endpoint (for admin, with role filter and search)
router.get('/users', authenticateToken, restrictToAdmin, async (req, res) => {
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
router.put('/users/:id', authenticateToken, restrictToAdmin, async (req, res) => {
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
router.delete('/users/:id', authenticateToken, restrictToAdmin, async (req, res) => {
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
router.get('/products', async (req, res) => {
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

router.post('/products', authenticateToken, restrictToAdmin, async (req, res) => {
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

router.put('/products/:id', authenticateToken, restrictToAdmin, async (req, res) => {
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

router.delete('/products/:id', authenticateToken, restrictToAdmin, async (req, res) => {
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
router.post('/inventory', authenticateToken, restrictToAdmin, async (req, res) => {
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

router.get('/inventory', authenticateToken, restrictToAdmin, async (req, res) => {
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

router.put('/inventory/:id', authenticateToken, restrictToAdmin, async (req, res) => {
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

module.exports = router;