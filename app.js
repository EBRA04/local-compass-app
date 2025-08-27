// Load environment variables first
require('dotenv').config();

const express = require('express');
const app = express();
const path = require('path');
const mongoose = require('mongoose');
const methodOverride = require('method-override');
const session = require('express-session');
const flash = require('connect-flash');
const bcrypt = require('bcrypt');
const mongoSanitize = require('express-mongo-sanitize');
const MongoStore = require('connect-mongo');

// Use environment variables with fallbacks
const dbUrl = process.env.DATABASE_URL;
const sessionSecret = process.env.SESSION_SECRET || 'development-secret-change-in-production';
const port = process.env.PORT || 3000;
const adminEmail = process.env.ADMIN_EMAIL || 'admin@localcompass.com';

// Check if DATABASE_URL is provided
if (!dbUrl) {
    console.error('❌ DATABASE_URL is not defined in .env file');
    process.exit(1);
}

//* MODELS
const Restaurant = require('./models/Restaurant');
const Review = require('./models/Reviews');
const User = require('./models/user'); 

//* Connect to MongoDB
mongoose.connect(dbUrl)
.then(() => {
    console.log('✅ MongoDB Connected successfully');
    console.log('Database URL:', dbUrl.replace(/:[^:@]+@/, ':***@')); // Hide password in logs
})
.catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
});

//* Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'public')));
// app.use(mongoSanitize({
//     replaceWith: '_'
// })); // Temporarily disabled due to compatibility issue

const store = MongoStore.create({
    mongoUrl: dbUrl,
    touchAfter: 24 * 60 * 60 // lazy session update
});

store.on("error", function(e) {
    console.log("SESSION STORE ERROR", e);
});

app.use(session({
    store,
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Enable secure cookies in production
        maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
    }
}));

app.use(flash());

//* Middleware to pass flash + current user to all views
app.use(async (req, res, next) => {
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    
    // Get full user object instead of just userId
    if (req.session.userId) {
        try {
            const user = await User.findById(req.session.userId);
            res.locals.currentUser = user;
            
            // Check if user is admin based on environment variable
            res.locals.isAdmin = user && user.email.toLowerCase() === adminEmail.toLowerCase();
        } catch (error) {
            console.error('Error fetching user:', error);
            res.locals.currentUser = null;
            res.locals.isAdmin = false;
        }
    } else {
        res.locals.currentUser = null;
        res.locals.isAdmin = false;
    }
    
    next();
});

// *---------------- AUTH ROUTES ----------------* //

//* Register GET
app.get('/register', (req, res) => {
    res.render('auth/register');
});

//* Register POST
app.post('/register', async (req, res) => {
    try {
        const { username, email, password, confirmPassword, fullName, terms } = req.body;

        //* Validation
        if (!email || !password || !confirmPassword || !fullName) {
            req.flash('error', 'All fields are required.');
            return res.redirect('/register');
        }
        if (password !== confirmPassword) {
            req.flash('error', 'Passwords do not match.');
            return res.redirect('/register');
        }
        if (password.length < 6) {
            req.flash('error', 'Password must be at least 6 characters long.');
            return res.redirect('/register');
        }
        if (!terms) {
            req.flash('error', 'You must agree to the terms.');
            return res.redirect('/register');
        }

        // * Check if email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            req.flash('error', 'Email already exists.');
            return res.redirect('/register');
        }

        const hashedPw = await bcrypt.hash(password, 10);
        const user = new User({
            username: username || email,
            email,
            password: hashedPw,
            fullName
        });

        await user.save();
        req.session.userId = user._id;
        console.log('Registered user:', user);
        
        // Check if new user is admin
        const isNewAdmin = user.email.toLowerCase() === adminEmail.toLowerCase();
        req.flash('success', `Welcome${isNewAdmin ? ' Admin' : ''}! You are registered and logged in.`);
        res.redirect('/');

    } catch (error) {
        console.error('Registration error:', error);
        req.flash('error', 'Registration failed. Please try again.');
        res.redirect('/register');
    }
});

// *Login GET
app.get('/login', (req, res) => {
    res.render('auth/login');
});

// * Login POST
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        console.log('=== LOGIN ATTEMPT ===');
        console.log('Email submitted:', email);
        console.log('Password provided:', password ? 'YES' : 'NO');
        
        // *Enhanced validation
        if (!email || !password) {
            console.log('❌ Missing email or password');
            req.flash('error', 'Both email and password are required.');
            return res.redirect('/login');
        }

        // *Trim whitespace and convert email to lowercase
        const cleanEmail = email.trim().toLowerCase();
        console.log('Cleaned email:', cleanEmail);

        // *Find user by email (case insensitive)
        const user = await User.findOne({ 
            email: { $regex: new RegExp(`^${cleanEmail}$`, 'i') }
        });
        
        console.log('User found:', user ? 'YES' : 'NO');
        
        if (user) {
            console.log('User details:', {
                id: user._id,
                email: user.email,
                username: user.username,
                fullName: user.fullName,
                isAdmin: user.email.toLowerCase() === adminEmail.toLowerCase(),
                hasStoredPassword: !!user.password
            });
        }
        
        if (!user) {
            console.log('❌ No user found with email:', cleanEmail);
            req.flash('error', 'Invalid email or password.');
            return res.redirect('/login');
        }

        //* Check if user has a password stored
        if (!user.password) {
            console.log('❌ User has no password stored');
            req.flash('error', 'Account error. Please contact support.');
            return res.redirect('/login');
        }

        //* Compare password using bcrypt
        console.log('Comparing password...');
        
        let valid = false;
        try {
            valid = await bcrypt.compare(password, user.password);
            console.log('Password comparison result:', valid);
        } catch (bcryptError) {
            console.error('❌ Bcrypt comparison error:', bcryptError);
            req.flash('error', 'Login failed. Please try again.');
            return res.redirect('/login');
        }
        
        if (!valid) {
            console.log('❌ Password comparison failed');
            
            //* Additional debug: try comparing with original password if it might not be hashed
            if (!user.password.startsWith('$2b$') && !user.password.startsWith('$2a$')) {
                console.log('⚠️ Password doesn\'t look hashed, trying direct comparison');
                if (password === user.password) {
                    console.log('✅ Direct password match - password was not hashed!');
                    //* Hash the password properly for future logins
                    const hashedPw = await bcrypt.hash(password, 10);
                    await User.findByIdAndUpdate(user._id, { password: hashedPw });
                    console.log('Password has been properly hashed for future use');
                    valid = true;
                }
            }
        }
        
        if (!valid) {
            req.flash('error', 'Invalid email or password.');
            return res.redirect('/login');
        }

        //* Set session and redirect
        req.session.userId = user._id;
        console.log('✅ Login successful for user:', user.email);
        console.log('Session userId set to:', req.session.userId);
        
        // Check if user is admin
        const isAdmin = user.email.toLowerCase() === adminEmail.toLowerCase();
        console.log('User is admin:', isAdmin);
        
        req.flash('success', `Welcome back${isAdmin ? ' Admin' : ''}!`);
        res.redirect('/');

    } catch (error) {
        console.error('❌ Login error:', error);
        console.error('Error stack:', error.stack);
        req.flash('error', 'Login failed. Please try again.');
        res.redirect('/login');
    }
});

//* Logout
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            req.flash('error', 'Could not log out, please try again.');
            return res.redirect('/');
        }
        res.redirect('/login');
    });
});

//* ---------------- MIDDLEWARE ---------------- //
function requireLogin(req, res, next) {
    if (!req.session.userId) {
        req.flash('error', 'You must be logged in first!');
        return res.redirect('/login');
    }
    next();
}

// Admin middleware - checks if email matches ADMIN_EMAIL
function requireAdmin(req, res, next) {
    if (!req.session.userId) {
        req.flash('error', 'You must be logged in first!');
        return res.redirect('/login');
    }
    
    // Check if user email matches admin email from environment
    if (!res.locals.currentUser || res.locals.currentUser.email.toLowerCase() !== adminEmail.toLowerCase()) {
        req.flash('error', 'Access denied. Admin privileges required.');
        return res.redirect('/restaurants');
    }
    
    next();
}

//* ---------------- RESTAURANT ROUTES ---------------- //
app.get('/', (req, res) => res.render('index'));

// Debug route to check users (remove this in production)
app.get('/debug/users', async (req, res) => {
    try {
        const users = await User.find({});
        res.json({
            totalUsers: users.length,
            users: users.map(u => ({
                id: u._id,
                email: u.email,
                username: u.username,
                fullName: u.fullName,
                hasPassword: !!u.password,
                passwordLength: u.password ? u.password.length : 0
            }))
        });
    } catch (error) {
        res.json({ error: error.message });
    }
});

app.get('/restaurants', requireLogin, async (req, res) => {
    try {
        const { location } = req.query; // ?location=Amman
        let restaurants;

        if (location) {
            restaurants = await Restaurant.find({ location: location });
        } else {
            restaurants = await Restaurant.find({});
        }

        
        res.render('restaurants/index', { 
            restaurants, 
            selectedLocation: location,
            isAdmin: res.locals.isAdmin  
        });
    } catch (err) {
        console.error('Error fetching restaurants:', err);
        req.flash('error', 'Could not load restaurants');
        res.redirect('/');
    }
});

// Only admin can create new restaurants
app.get('/restaurants/new', requireLogin, requireAdmin, (req, res) => res.render('restaurants/new'));

app.post('/restaurants', requireLogin, requireAdmin, async (req, res) => {
    try {
        const restaurant = new Restaurant(req.body);
        await restaurant.save();
        req.flash('success', 'Restaurant added successfully!');
        res.redirect('/restaurants');
    } catch (error) {
        console.error('Error adding restaurant:', error);
        req.flash('error', 'Could not add restaurant');
        res.redirect('/restaurants/new');
    }
});

app.get('/restaurants/:id', requireLogin, async (req, res) => {
    try {
        const restaurant = await Restaurant.findById(req.params.id).populate('reviews');
        if (!restaurant) {
            req.flash('error', 'Restaurant not found');
            return res.redirect('/restaurants');
        }
        res.render('restaurants/show', { restaurant });
    } catch (error) {
        console.error('Error fetching restaurant:', error);
        req.flash('error', 'Could not load restaurant');
        res.redirect('/restaurants');
    }
});

// Only admin can edit restaurants
app.get('/restaurants/:id/edit', requireLogin, requireAdmin, async (req, res) => {
    try {
        const restaurant = await Restaurant.findById(req.params.id);
        if (!restaurant) {
            req.flash('error', 'Restaurant not found');
            return res.redirect('/restaurants');
        }
        res.render('restaurants/edit', { restaurant });
    } catch (error) {
        console.error('Error fetching restaurant:', error);
        req.flash('error', 'Could not load restaurant');
        res.redirect('/restaurants');
    }
});

app.put('/restaurants/:id', requireLogin, requireAdmin, async (req, res) => {
    try {
        await Restaurant.findByIdAndUpdate(req.params.id, req.body);
        req.flash('success', 'Restaurant updated successfully!');
        res.redirect(`/restaurants/${req.params.id}`);
    } catch (error) {
        console.error('Error updating restaurant:', error);
        req.flash('error', 'Could not update restaurant');
        res.redirect(`/restaurants/${req.params.id}/edit`);
    }
});

// Only admin can delete restaurants
app.delete('/restaurants/:id', requireLogin, requireAdmin, async (req, res) => {
    try {
        await Restaurant.findByIdAndDelete(req.params.id);
        req.flash('success', 'Restaurant deleted successfully!');
        res.redirect('/restaurants');
    } catch (error) {
        console.error('Error deleting restaurant:', error);
        req.flash('error', 'Could not delete restaurant');
        res.redirect('/restaurants');
    }
});

// Contact page route - FIXED
app.get('/contact', (req, res) => {
    res.render('restaurants/contact', {
        currentUser: res.locals.currentUser,
        isAdmin: res.locals.isAdmin
    });
});

//* ---------------- REVIEW ROUTES ---------------- //
// All logged-in users can add reviews
app.post('/restaurants/:id/reviews', requireLogin, async (req, res) => {
    try {
        const restaurant = await Restaurant.findById(req.params.id);
        const review = new Review(req.body);
        restaurant.reviews.push(review);
        await review.save();
        await restaurant.save();
        req.flash('success', 'Review added successfully!');
        res.redirect(`/restaurants/${restaurant._id}`);
    } catch (error) {
        console.error('Error adding review:', error);
        req.flash('error', 'Could not add review');
        res.redirect(`/restaurants/${req.params.id}`);
    }
});

// Only admin can delete reviews
app.delete('/restaurants/:id/reviews/:reviewId', requireLogin, requireAdmin, async (req, res) => {
    try {
        const { id, reviewId } = req.params;
        await Restaurant.findByIdAndUpdate(id, { $pull: { reviews: reviewId } });
        await Review.findByIdAndDelete(reviewId);
        req.flash('success', 'Review deleted successfully!');
        res.redirect(`/restaurants/${id}`);
    } catch (error) {
        console.error('Error deleting review:', error);
        req.flash('error', 'Could not delete review');
        res.redirect(`/restaurants/${req.params.id}`);
    }
});

//* Start server
app.listen(port, () => console.log(`Server running on port ${port}`));