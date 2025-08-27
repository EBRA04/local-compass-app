const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const RestaurantSchema = new Schema({
    title: String,
    location: String,
    lat: Number, 
    lng: Number,
    cuisine: String,
    description: String,
    reviews:[
        {
            type:Schema.Types.ObjectId,
            ref:'Review'
        }
    ]
});

module.exports = mongoose.model('Restaurant', RestaurantSchema);
