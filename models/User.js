const mongoose = require('mongoose');

  const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    password: { type: String, required: true },
    address: { type: String, required: true },
    pincode: { type: String, required: true },
    building: { type: String },
    role: {
      type: String,
      enum: ['customer', 'admin', 'packer', 'delivery'],
      default: 'customer'
    },
    createdAt: { type: Date, default: Date.now }
  });

  module.exports = mongoose.model('User', UserSchema);