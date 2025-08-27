const mongoose = require('mongoose');
const Restaurant = require('../models/Restaurant'); // path to your Restaurant model
const restaurants = require('./restaurants'); // your updated restaurants.js

mongoose.connect('mongodb://localhost:27017/RestaurantDB', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', async () => {
    console.log('Connected to MongoDB');

    await Restaurant.deleteMany({});

    await Restaurant.insertMany(restaurants);
    console.log('Database updated with new restaurants');

    mongoose.connection.close();
});
