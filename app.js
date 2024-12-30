const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

const cookieParser = require("cookie-parser");
const path = require("path");
const userModel = require("./models/user");

// Middleware
app.set("view engine", "ejs");
app.use(express.json());
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
require("dotenv").config();

// Mongoose connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
    .then(() => console.log('Connected to MongoDB'))
    .catch((error) => console.error('Error connecting to MongoDB:', error));

// Routes
app.get("/", (req, res) => {
    res.render("index");
});

// POST route to create a new user
app.post("/create", (req, res) => {
    const { username, email, password, age } = req.body;

    bcrypt.genSalt(10, (err, salt) => {
        if (err) return res.send("Error generating salt");
        bcrypt.hash(password, salt, async (err, hash) => {
            if (err) return res.send("Error hashing password");

            let createdUser = await userModel.create({
                username,
                email,
                password: hash,
                age
            });

            let token = jwt.sign({ email }, "secretKey");
            res.cookie("token", token);
            res.status(201).send("User created successfully");
        });
    });
});

// Login route
app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/login", async (req, res) => {
    let user = await userModel.findOne({ email: req.body.email });
    if (!user) return res.send("Invalid email or password");

    bcrypt.compare(req.body.password, user.password, (err, result) => {
        if (err) return res.send("Error during password comparison");
        if (result) {
            //token user brower nhej rhe hai 
            let token = jwt.sign({ email:user.email }, "secretKey");
            res.cookie("token", token);

            res.send("You are logged in");
        } else {
            res.send("Invalid email or password");
        }
    });
});

// Logout route
app.get("/logout", function (req, res) {
    res.clearCookie("token");
    res.redirect("/");
});

// Server setup
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
