import express from 'express';
import mysql from 'mysql2/promise';  // Use the 'mysql2/promise' import
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
const port = 3000;

// Middleware
app.use(express.json());

// MySQL Database connection using promise API
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'shop_management',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

  
// JWT Secret Key
const secretKey = 'your_secret_key';

// Generate JWT Token
const generateToken = (user) => {
    return jwt.sign(
      {
        role: user.role,
        shop_id: user.shop_id,
        manager_id: user.manager_id,
        email: user.email
      },
      secretKey,
      { expiresIn: '1h' }
    );
  };
  
  
  // Token Verification Middleware
  const verifyToken = (req, res, next) => {
    const authHeader = req.header('Authorization');
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) return res.status(401).send('Access Denied. No token provided.');
  
    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) return res.status(400).send('Invalid token.');
        console.log('Decoded Token:', decoded);  // 👈 Add this
        req.user = decoded;
        next();
      });
  };
  
  
  
// 1. Admin Creates Manager
app.post('/admin/create-manager', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') {
      return res.status(403).send('Access denied. Only admin can create managers.');
    }
  
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
  
    try {
      await pool.query(
        'INSERT INTO users (email, password, role) VALUES (?, ?, ?)', 
        [email, hashedPassword, 'manager']
      );
      res.status(201).send('Manager created successfully');
    } catch (err) {
      console.error('Error creating manager:', err);  // 👈 Add this for debugging
      res.status(500).send(err);
    }
  });
  

// Create Admin Route
app.post('/admin/create', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      // Get connection from the pool
      const connection = await pool.getConnection();
  
      // Check if the admin already exists
      const [adminExists] = await connection.execute('SELECT * FROM admins WHERE email = ?', [email]);
      if (adminExists.length > 0) {
        connection.release();
        return res.status(400).json({ message: 'Admin already exists.' });
      }
  
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Insert admin into the database
      const [result] = await connection.execute('INSERT INTO admins (email, password) VALUES (?, ?)', [email, hashedPassword]);
      
      console.log('Admin created:', result);  // Log the result for debugging
      connection.release();  // Release the connection back to the pool
      res.status(201).json({ message: 'Admin created successfully.' });
    } catch (err) {
      console.error('Error creating admin:', err);  // Log the actual error
      res.status(500).json({ message: 'Error creating admin', error: err.message });
    }
  });
// 2. Manager Login (Shop's Email)
app.post('/manager/login-shop', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      const [shopResults] = await pool.query('SELECT * FROM shops WHERE email = ?', [email]);
      
      if (shopResults.length === 0) return res.status(404).send('Shop not found.');
      
      const shop = shopResults[0];
      const isPasswordValid = await bcrypt.compare(password, shop.password);
  
      if (!isPasswordValid) return res.status(400).send('Invalid password.');
  
      const token = generateToken({
        role: 'manager',
        shop_id: shop.id,
        manager_id: shop.manager_id,
        email: shop.email
      });
  
      res.status(200).json({ token });
    } catch (err) {
      res.status(500).send(err);
    }
  });
  

// 3. Manager Creates Shop
app.post('/manager/create-shop', verifyToken, async (req, res) => {
    if (req.user.role !== 'manager') {
      return res.status(403).send('Access denied. Only managers can create shops.');
    }
  
    const { name, email, password, location } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
  
    try {
      await pool.query(
        'INSERT INTO shops (name, email, password, location, manager_id) VALUES (?, ?, ?, ?, ?)', 
        [name, email, hashedPassword, location, req.user.manager_id]
      );
      res.status(201).send('Shop created successfully');
    } catch (err) {
      console.error('Error creating shop:', err);
      res.status(500).send('Error creating shop');
    }
  });
  

// 4. Manager Creates Product for Shop
// 4. Manager Creates Product for Their Shop
app.post('/manager/create-product', verifyToken, async (req, res) => {
    const { name, price, description, stock } = req.body;
  
    // Ensure that the manager can only create products for their own shop
    if (req.user.role !== 'manager') {
      return res.status(403).send('Access denied. Only managers can create products.');
    }
  
    // Validate the shop_id from the token and request body match
    const shop_id_from_token = req.user.shop_id;  // Shop ID from the token
    const shop_id_from_request = req.body.shop_id;  // Shop ID from the request body
  
    if (shop_id_from_token !== shop_id_from_request) {
      return res.status(403).send('Access denied. You can only create products for your shop.');
    }
  
    try {
      // Insert the product into the database, linking it to the correct shop
      const [result] = await pool.query(
        'INSERT INTO products (name, price, description, stock, shop_id) VALUES (?, ?, ?, ?, ?)', 
        [name, price, description, stock, shop_id_from_token]
      );
  
      res.status(201).send('Product created successfully');
    } catch (err) {
      console.error('Error creating product:', err);
      res.status(500).send('Error creating product');
    }
  });
  
// Manager Login Route
app.post('/manager/login', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      const [users] = await pool.query('SELECT * FROM users WHERE email = ? AND role = ?', [email, 'manager']);
  
      if (users.length === 0) {
        return res.status(404).send('Manager not found.');
      }
  
      const manager = users[0];
      const isPasswordValid = await bcrypt.compare(password, manager.password);
  
      if (!isPasswordValid) {
        return res.status(400).send('Invalid password.');
      }
  
      const token = jwt.sign(
        {
          role: 'manager',
          email: manager.email,
          manager_id: manager.id // assuming 'id' is the primary key in 'users'
        },
        secretKey,
        { expiresIn: '1h' }
      );
  
      res.status(200).json({ token });
  
    } catch (err) {
      console.error('Error logging in manager:', err);
      res.status(500).json({ message: 'Error logging in manager', error: err.message });
    }
  });
  
// 5. View Products for Shop
// 5. View Products for Manager's Shop
app.get('/manager/products', verifyToken, async (req, res) => {
    const shop_id = req.user.shop_id;  // Get the shop_id from the token
  
    try {
      const [products] = await pool.query('SELECT * FROM products WHERE shop_id = ?', [shop_id]);
      res.status(200).json(products);  // Return the products that belong to the manager's shop
    } catch (err) {
      console.error('Error retrieving products:', err);
      res.status(500).send('Error retrieving products');
    }
  });
  
// Admin Login Route
app.post('/admin/login', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      // Fetch the admin from the database using the pool connection
      const [admin] = await pool.query('SELECT * FROM admins WHERE email = ?', [email]);
  
      // Check if admin exists
      if (admin.length === 0) {
        return res.status(404).send('Admin not found.');
      }
  
      // Log admin for debugging (optional)
      console.log('Admin found:', admin[0]);
  
      // Compare the provided password with the hashed password in the database
      const isPasswordValid = await bcrypt.compare(password, admin[0].password);
  
      // If password is incorrect
      if (!isPasswordValid) {
        return res.status(400).send('Invalid password.');
      }
  
      // ✅ Generate a JWT token including the admin role
      const token = jwt.sign(
        {
          role: 'admin',
          email: admin[0].email,
          admin_id: admin[0].id
        },
        secretKey,
        { expiresIn: '1h' }
      );
  
      // Send the token back as the response
      res.status(200).json({ token });
  
    } catch (err) {
      console.error('Error logging in admin:', err);
      res.status(500).json({ message: 'Error logging in admin', error: err.message });
    }
  });
  // Checkout - Process Cart and move to Sold Products
app.post('/cart/checkout', verifyToken, async (req, res) => {
    const user_id = req.user.id;
  
    try {
      // Get products in the user's cart
      const [cartItems] = await pool.query(`
        SELECT c.product_id, c.quantity, p.stock
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ?`, [user_id]);
  
      // Check if stock is available
      for (let item of cartItems) {
        if (item.quantity > item.stock) {
          return res.status(400).send(`Not enough stock for product ID ${item.product_id}`);
        }
      }
  
      // Process each item in the cart
      for (let item of cartItems) {
        // Reduce stock in the products table
        await pool.query('UPDATE products SET stock = stock - ? WHERE id = ?', [item.quantity, item.product_id]);
  
        // Add item to sold_products table
        await pool.query('INSERT INTO sold_products (product_id, quantity) VALUES (?, ?)', [item.product_id, item.quantity]);
  
        // Remove item from cart
        await pool.query('DELETE FROM cart WHERE user_id = ? AND product_id = ?', [user_id, item.product_id]);
      }
  
      res.status(200).send('Checkout successful. Products moved to sold and stock updated.');
    } catch (err) {
      console.error('Error processing checkout:', err);
      res.status(500).send('Error processing checkout');
    }
  });
// View cart
app.get('/cart', verifyToken, async (req, res) => {
    const user_id = req.user.id;
  
    try {
      // Get products in the user's cart
      const [cart] = await pool.query(`
        SELECT p.id, p.name, p.price, p.stock, c.quantity
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ?`, [user_id]);
  
      res.status(200).json(cart); // Return cart products
    } catch (err) {
      console.error('Error fetching cart:', err);
      res.status(500).send('Error fetching cart');
    }
  });
// Add product to cart
app.post('/cart/add', verifyToken, async (req, res) => {
    const { product_id, quantity } = req.body;
    const user_id = req.user.id; // assuming the user id is in the token
  
    try {
      // Check if product exists
      const [product] = await pool.query('SELECT * FROM products WHERE id = ?', [product_id]);
      if (product.length === 0) return res.status(404).send('Product not found.');
  
      // Insert product into cart
      await pool.query('INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)', [user_id, product_id, quantity]);
  
      res.status(201).send('Product added to cart.');
    } catch (err) {
      console.error('Error adding product to cart:', err);
      res.status(500).send('Error adding product to cart');
    }
  });
      
// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
