const express = require('express');
const router = express.Router();
const { authenticateToken, restrictToRoles } = require('../middleware/auth');
const Order = require('../models/Order');
const Inventory = require('../models/Inventory');
const Product = require('../models/Product');
const mongoose = require('mongoose'); // Added for ObjectId

// Get Orders for Packer (only pending orders)
router.get('/orders', authenticateToken, restrictToRoles(['packer']), async (req, res) => {
  try {
    const { date, search } = req.query;
    let query = { status: 'pending' };

    // Filter by date (ignoring time)
    if (date) {
      const startDate = new Date(date);
      startDate.setHours(0, 0, 0, 0);
      const endDate = new Date(date);
      endDate.setHours(23, 59, 59, 999);
      query.createdAt = { $gte: startDate, $lte: endDate };
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

// Update Order Status to Packed (for packers)
router.put('/orders/:id', authenticateToken, restrictToRoles(['packer']), async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (status !== 'packed') {
    return res.status(400).json({ error: 'Packers can only update status to packed' });
  }

  try {
    const order = await Order.findById(id);
    if (!order) return res.status(404).json({ error: 'Order not found' });

    // Ensure stock is still available
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

    order.status = status;
    await order.save();
    res.json(order);
  } catch (err) {
    console.error('Update order status error:', err);
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

module.exports = router;