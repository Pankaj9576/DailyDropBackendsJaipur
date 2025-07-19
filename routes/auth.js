const express = require('express');
  const bcrypt = require('bcryptjs');
  const jwt = require('jsonwebtoken');
  const User = require('../models/User');
  const router = express.Router();

  // Register Route
  router.post('/register', async (req, res) => {
    const { name, email, phone, password, address, pincode, building } = req.body;

    try {
      // Check if user already exists
      let user = await User.findOne({ email });
      if (user) {
        return res.status(400).json({ error: 'Email already exists' });
      }

      // Validate pincode (mock 3km check)
      const eligiblePincodes = ['302001', '302002', '302003', '302004'];
      if (!eligiblePincodes.includes(pincode)) {
        return res.status(400).json({
          error: 'Location is outside delivery range (3km). We serve: 302001, 302002, 302003, 302004'
        });
      }

      // Hash password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Create new user
      user = new User({
        name,
        email,
        phone,
        password: hashedPassword,
        address,
        pincode,
        building,
        role: 'customer' // Default role
      });

      await user.save();

      // Generate JWT
      const token = jwt.sign(
        { userId: user._id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      res.json({
        token,
        user: { id: user._id, name, email, role: user.role }
      });
    } catch (err) {
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Login Route
  router.post('/login', async (req, res) => {
    const { email, password, role } = req.body;

    try {
      // Check if user exists
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }

      // Check password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }

      // Check role
      if (user.role !== role) {
        return res.status(400).json({ error: 'Invalid role selected' });
      }

      // Generate JWT
      const token = jwt.sign(
        { userId: user._id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      res.json({
        token,
        user: { id: user._id, name: user.name, email, role: user.role }
      });
    } catch (err) {
      res.status(500).json({ error: 'Server error' });
    }
  });

  module.exports = router;