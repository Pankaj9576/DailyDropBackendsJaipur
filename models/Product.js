const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  unit: { type: String, required: true },
  emoji: { type: String },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Product', productSchema);