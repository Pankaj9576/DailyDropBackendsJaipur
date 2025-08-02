const express = require('express');
const router = express.Router();
const { authenticateToken, restrictToRoles } = require('../middleware/auth');
const Order = require('../models/Order');

// Get Orders for Delivery (only packed or out_for_delivery orders)
router.get('/orders', authenticateToken, restrictToRoles(['delivery']), async (req, res) => {
  try {
    const { date, search } = req.query;
    let query = { status: { $in: ['packed', 'out_for_delivery'] } };

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

// Update Order Status to Out for Delivery or Delivered (for delivery)
router.put('/orders/:id', authenticateToken, restrictToRoles(['delivery']), async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!['out_for_delivery', 'delivered'].includes(status)) {
    return res.status(400).json({ error: 'Delivery personnel can only update status to out_for_delivery or delivered' });
  }

  try {
    const order = await Order.findById(id);
    if (!order) return res.status(404).json({ error: 'Order not found' });

    order.status = status;
    await order.save();
    res.json(order);
  } catch (err) {
    console.error('Update order status error:', err);
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

module.exports = router;