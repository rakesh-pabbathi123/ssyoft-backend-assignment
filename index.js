const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const dbPath = path.join(__dirname, "database.db");
let db = null;

// Initialize database connection
const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
  } catch (error) {
    console.log(`DB Error: ${error.message}`);
    process.exit(1);
  }
};
initializeDbAndServer();

// Helper function to check if user exists
const checkUserExists = async (username, email) => {
  const userCheckQuery = `SELECT * FROM users WHERE username = ? OR email = ?;`;
  return db.get(userCheckQuery, [username, email]);
};

// API: Register New User
app.post("/register/", async (request, response) => {
  try {
    const { username, password, email, role } = request.body;

    if (!username || !password || !email || !role) {
      return response.status(400).send("All fields are required");
    }

    // Check if user already exists
    const dbUser = await checkUserExists(username, email);

    if (dbUser) {
      return response.status(400).send("User already exists");
    }

    if (password.length < 6) {
      return response.status(400).send("Password is too short");
    }

    if (!["admin", "manager", "staff"].includes(role)) {
      return response.status(400).send("Invalid role");
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user
    const registerUserQuery = `
      INSERT INTO 
        users (username, email, password, role)
      VALUES
        (?, ?, ?, ?);`;
    await db.run(registerUserQuery, [username, email, hashedPassword, role]);

    response.send("User created successfully");
  } catch (error) {
    response.status(500).send("Server error");
  }
});

// Middleware for Authorization
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).send("Token not provided");
  }

  jwt.verify(token, "SECRET_KEY", (err, user) => {
    if (err) {
      return res.status(403).send("Invalid Token");
    }
    req.user = user;
    next();
  });
};

const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).send("Access denied");
    }
    next();
  };
};

// API: Login User
app.post("/login", async (request, response) => {
  const { email, password } = request.body;

  // Validate input
  if (!email || !password) {
    return response.status(400).send("Email and password are required");
  }

  try {
    // Fetch user from the database using email
    const selectUserQuery = `SELECT * FROM users WHERE email = ?`;
    const dbUser = await db.get(selectUserQuery, [email]);

    if (!dbUser) {
      // User not found
      return response.status(400).send("Invalid email or password");
    }

    // Check password
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password);

    if (isPasswordMatched) {
      // Password matches
      const payload = { username: dbUser.username, role: dbUser.role };
      const jwtToken = jwt.sign(payload, "SECRET_KEY", { expiresIn: "1h" });
      response.status(200).json({ jwtToken });
    } else {
      // Password does not match
      response.status(400).send("Invalid email or password");
    }
  } catch (error) {
    // Handle unexpected errors
    console.error("Login Error:", error);
    response.status(500).send("Server error");
  }
});

// API: Create Product
app.post(
  "/products/",
  authenticateToken,
  authorizeRole(["admin"]),
  async (req, res) => {
    const { title, description, inventoryCount } = req.body;

    if (!title || !description || inventoryCount === undefined) {
      return res.status(400).send("All fields are required");
    }

    try {
      const insertProductQuery = `
      INSERT INTO products (title, description, inventoryCount)
      VALUES (?, ?, ?);`;
      await db.run(insertProductQuery, [title, description, inventoryCount]);
      res.status(201).json({ message: "Product created successfully" });
    } catch (error) {
      console.error("Error creating product:", error);
      res.status(500).send("Server error");
    }
  }
);

app.listen(3003, () => {
  console.log("Server is running on http://localhost:3003");
});
