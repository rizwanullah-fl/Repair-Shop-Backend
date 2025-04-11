const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(bodyParser.json());

const SECRET_KEY = process.env.SECRET_KEY || "your_secret_key";

// Database Connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "shops",
    connectionLimit: 10, // Adjust based on your needs
    queueLimit: 0
});

db.connect(err => {
    if (err) console.error("DB Connection Error:", err);
    else console.log("Connected to MySQL");
});

// 🔹 **Middleware to Verify JWT Token**
function authenticateToken(req, res, next) {
    const token = req.header("Authorization")?.split(" ")[1]; // Extract the token from the "Authorization: Bearer <token>"

    if (!token) return res.status(401).json({ message: "No token provided" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid Token" });
        req.user = user; // Attach the decoded user data to the request object
        next();
    });
}

// 🔹 **User Signup**
app.post("/signup", async (req, res) => {
    const { name, email, password, shop_name, shop_address } = req.body;

    // Validate required fields
    if (!name || !email || !password || !shop_name || !shop_address) {
        return res.status(400).json({ message: "All fields are required" });
    }

    // Check if user already exists with the same email
    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
        if (err) return res.status(500).send(err);
        if (result.length > 0) {
            return res.status(400).json({ message: "Email is already registered. Please try with a different email." });
        }

        // Create new shop (add shop to the shops table)
        db.query(
            "INSERT INTO shops (name, address) VALUES (?, ?)",
            [shop_name, shop_address],
            (err, result) => {
                if (err) return res.status(500).send(err);

                const shop_id = result.insertId; // Get the newly created shop's ID

                // Hash Password
                bcrypt.hash(password, 10, (err, hashedPassword) => {
                    if (err) return res.status(500).send(err);

                    // Check if the email is admin@gmail.com
                    const role = email === "admin@gmail.com" ? "admin" : "user"; // Assign "admin" role to admin@gmail.com

                    // Insert user with the new shop_id and role
                    db.query(
                        "INSERT INTO users (shop_id, name, email, password, role) VALUES (?, ?, ?, ?, ?)",
                        [shop_id, name, email, hashedPassword, role],
                        (err, result) => {
                            if (err) return res.status(500).send(err);

                            // Generate JWT Token
                            const token = jwt.sign({ id: result.insertId, shop_id: shop_id, role: role }, SECRET_KEY, { expiresIn: "7d" });

                            // Fetch the shop name
                            db.query("SELECT name FROM shops WHERE id = ?", [shop_id], (err, shopResult) => {
                                if (err) return res.status(500).send(err);

                                // Respond with user, shop name, role, and token
                                res.json({
                                    message: "User registered successfully",
                                    user: {
                                        name: name,
                                        shop_name: shopResult[0].name,
                                        role: role,
                                        token: token
                                    }
                                });
                            });
                        }
                    );
                });
            }
        );
    });
});


// 🔹 **User Login**
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    // Fetch user from the database by email
    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, result) => {
        if (err) return res.status(500).send(err);
        if (result.length === 0) return res.status(400).json({ message: "Invalid credentials" });

        const user = result[0];

        // Compare the password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

        // Fetch the shop name using the shop_id from the user table
        db.query("SELECT name FROM shops WHERE id = ?", [user.shop_id], (err, shopResult) => {
            if (err) return res.status(500).send(err);
            if (shopResult.length === 0) return res.status(400).json({ message: "Shop not found" });

            const shop_name = shopResult[0].name; // Get shop name

            // Generate JWT Token
            const token = jwt.sign({ id: user.id, shop_id: user.shop_id, role: user.role }, SECRET_KEY, { expiresIn: "7d" });

            // Send response with the user info and token
            res.json({
                message: "Login successful",
                user: {
                    id: user.id,
                    name: user.name,
                    shop_name: shop_name,
                    role: user.role,
                    token: token
                }
            });
        });
    });
});


// 🔹 **Protected Route - Get User Details**
app.get("/user", authenticateToken, (req, res) => {
    db.query("SELECT id, name, email, role FROM users WHERE id = ?", [req.user.id], (err, result) => {
        if (err) return res.status(500).send(err);
        res.json(result[0]);
    });
});

// 🔹 **Get All Shops**
app.get("/shops", authenticateToken, (req, res) => {
    db.query("SELECT * FROM shops", (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results);
    });
});
// 🔹 **Get Products for a User**
app.get("/user-products", authenticateToken, (req, res) => {
    const userId = req.user.id; // Get user ID from the decoded token

    db.query("SELECT * FROM products WHERE user_id = ?", [userId], (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results); // Send the products associated with the logged-in user
    });
});



app.post("/add-product", authenticateToken, (req, res) => {
    const { name, price, quantity } = req.body;
    const userId = req.user.id; // Get user ID from the decoded token

    // Insert the new product into the products table
    db.query(
        "INSERT INTO products (user_id, name, price, quantity) VALUES (?, ?, ?, ?)",
        [userId, name, price, quantity],
        (err, result) => {
            if (err) return res.status(500).send(err);

            // After adding the product, insert a record into product_history
            db.query(
                "INSERT INTO product_history (user_id, product_name, price, quantity) VALUES (?, ?, ?, ?)",
                [userId, name, price, quantity],
                (err, historyResult) => {
                    if (err) return res.status(500).send(err);
                    res.json({ message: "Product added successfully, history logged", id: result.insertId });
                }
            );
        }
    );
});

// 🔹 **Get Product History**
app.get("/product-history", authenticateToken, (req, res) => {
    const userId = req.user.id; // Get user ID from the decoded token

    db.query(
        "SELECT * FROM product_history WHERE user_id = ? ORDER BY created_at DESC", 
        [userId], 
        (err, result) => {
            if (err) return res.status(500).send(err);
            if (result.length === 0) return res.status(404).json({ message: "No product history found" });

            res.json({
                message: "Product history fetched successfully",
                history: result
            });
        }
    );
});
// 🔹 **Delete Product**
app.delete("/delete-product/:id", authenticateToken, (req, res) => {
    const productId = req.params.id; // Get the product ID from the URL
    const userId = req.user.id; // Get the user ID from the decoded token

    // Check if the product exists and if the current user is the one who added it
    db.query("SELECT * FROM products WHERE id = ? AND user_id = ?", [productId, userId], (err, result) => {
        if (err) return res.status(500).send(err);
        if (result.length === 0) {
            return res.status(404).json({ message: "Product not found or not authorized to delete" });
        }

        // Proceed to delete the product
        db.query("DELETE FROM products WHERE id = ?", [productId], (err) => {
            if (err) return res.status(500).send(err);

            res.json({ message: "Product deleted successfully" });
        });
    });
});



// 🔹 **Add to Cart**
app.post("/add-to-cart", authenticateToken, (req, res) => {
    const { product_id, quantity } = req.body;

    // Validate the data (check if product_id and quantity are provided)
    if (!product_id || !quantity) {
        return res.status(400).json({ message: "Product ID and quantity are required" });
    }

    // Validate that quantity is a positive integer
    if (isNaN(quantity) || quantity <= 0) {
        return res.status(400).json({ message: "Quantity must be a positive integer" });
    }

    // Check if the product exists and has sufficient stock
    db.query("SELECT quantity FROM products WHERE id = ?", [product_id], (err, results) => {
        if (err) return res.status(500).send(err);
        if (results.length === 0) {
            return res.status(400).json({ message: "Product not found" });
        }

        // Check if there's enough stock
        if (results[0].quantity < quantity) {
            return res.status(400).json({ message: "Insufficient stock" });
        }

        // If everything is fine, proceed to add the product to the cart
        db.query(
            "INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)",
            [req.user.id, product_id, quantity],
            (err, result) => {
                if (err) return res.status(500).send(err);
                res.json({ message: "Added to cart", id: result.insertId });
            }
        );
    });
});


app.post("/checkout", authenticateToken, async (req, res) => {
    const connection = await db.promise(); // Use promise-based API of mysql2

    try {
        // Start a transaction
        await connection.beginTransaction();

        // Fetch cart items for the user
        const [cartItems] = await connection.query("SELECT * FROM cart WHERE user_id = ?", [req.user.id]);

        if (cartItems.length === 0) {
            return res.status(400).json({ message: "Cart is empty" });
        }

        // Prepare product details for history
        const productDetails = [];
        let totalAmount = 0;

        // Check stock and update quantities
        for (const item of cartItems) {
            const [product] = await connection.query("SELECT * FROM products WHERE id = ?", [item.product_id]);

            if (product.length === 0) {
                throw new Error("Product not found");
            }

            // Check if there's enough stock
            if (product[0].quantity < item.quantity) {
                throw new Error(`Not enough stock for product ID ${item.product_id}`);
            }

            // Calculate total amount for this product
            const amount = product[0].price * item.quantity;
            totalAmount += amount;

            // Add product details for history
            productDetails.push({
                product_id: item.product_id,
                quantity: item.quantity,
                price: product[0].price,
                amount: amount
            });

            // Decrease stock
            await connection.query("UPDATE products SET quantity = quantity - ? WHERE id = ?", [item.quantity, item.product_id]);
        }

        // Insert the checkout history into the database
        await connection.query(
            "INSERT INTO checkout_history (user_id, product_details, total_amount) VALUES (?, ?, ?)",
            [req.user.id, JSON.stringify(productDetails), totalAmount]
        );

        // Delete cart items after processing checkout
        await connection.query("DELETE FROM cart WHERE user_id = ?", [req.user.id]);

        // Commit the transaction
        await connection.commit();

        res.json({ message: "Checkout successful, products updated!" });
    } catch (err) {
        // Rollback the transaction in case of an error
        await connection.rollback();
        res.status(500).json({ message: err.message || "Something went wrong" });
    }
});
app.get("/checkout-history", authenticateToken, async (req, res) => {
    console.log('Checkout history request received'); // Log to check if the route is hit
    const connection = await db.promise();

    try {
        const [history] = await connection.query("SELECT * FROM checkout_history WHERE user_id = ?", [req.user.id]);
        if (history.length === 0) {
            return res.status(404).json({ message: "No checkout history found" });
        }
        res.json(history);
    } catch (err) {
        console.error(err);  // Log the error
        res.status(500).json({ message: err.message || "Something went wrong" });
    }
});


function isAdmin(req, res, next) {
    if (req.user.role !== "admin") {
        return res.status(403).json({ message: "Access denied" });
    }
    next();
}

app.get("/admin-dashboard", authenticateToken, isAdmin, (req, res) => {
    // Admin-specific functionality here
    res.json({ message: "Welcome to the admin dashboard!" });
});

app.listen(3000, () => console.log("Server running on port 3000"));


