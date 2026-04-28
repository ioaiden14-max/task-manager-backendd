require("dotenv").config();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { sql, connectDB } = require("./db");
const express = require("express");
const cors = require("cors");

const app = express();

// middleware
app.use(cors());
app.use(express.json());
connectDB();

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const request = new sql.Request();
    request.input("username", sql.NVarChar, username);
    request.input("password", sql.NVarChar, hashedPassword);

    await request.query(`
      INSERT INTO Users (username, password)
      VALUES (@username, @password)
    `);

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  try {
    const request = new sql.Request();
    request.input("username", sql.NVarChar, username);

    const result = await request.query(`
      SELECT * FROM Users WHERE username = @username
    `);

    if (result.recordset.length === 0) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const user = result.recordset[0];

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({ message: "Access denied. No token provided." });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // attach user info
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid token" });
  }
};

// sample data (temporary, no database yet)
let tasks = [
  {
    id: 1,
    title: "Study React",
    description: "Practice components and routing",
    completed: false,
  },
  {
    id: 2,
    title: "Gym",
    description: "Leg day",
    completed: true,
  },
];

// test route
app.get("/", (req, res) => {
  res.send("Backend is running");
});

// GET all tasks
// GET all tasks
app.get("/tasks", authMiddleware, async (req, res) => {
  const userId = req.user.id;

  try {
    const request = new sql.Request();
    request.input("userId", sql.Int, userId);

    const result = await request.query(`
      SELECT * FROM Tasks
      WHERE userId = @userId
    `);

    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
// POST new task
app.post("/tasks", authMiddleware, async (req, res) => {
  const { title, description } = req.body;
  const userId = req.user.id;

  if (!title || !description) {
    return res.status(400).json({
      message: "Title and description are required",
    });
  }

  try {
    const request = new sql.Request();

    request.input("title", sql.NVarChar, title);
    request.input("description", sql.NVarChar, description);
    request.input("userId", sql.Int, userId);

    const result = await request.query(`
      INSERT INTO Tasks (title, description, userId)
      OUTPUT INSERTED.*
      VALUES (@title, @description, @userId)
    `);

    res.status(201).json(result.recordset[0]);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
// DELETE task
app.delete("/tasks/:id", authMiddleware, async (req, res) => {
  const id = Number(req.params.id);

  try {
    const result = await sql.query(`
      DELETE FROM Tasks
      OUTPUT DELETED.*
      WHERE id = ${id}
    `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: "Task not found" });
    }

    res.json({ message: "Task deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
// UPDATE task
// UPDATE task
app.put("/tasks/:id", authMiddleware, async (req, res) => {
  const id = Number(req.params.id);
  const { title, description, completed } = req.body;

  try {
    const request = new sql.Request();

    request.input("id", sql.Int, id);
    request.input("title", sql.NVarChar, title ?? null);
    request.input("description", sql.NVarChar, description ?? null);
    request.input(
      "completed",
      sql.Bit,
      completed === undefined ? null : completed
    );

    const result = await request.query(`
      UPDATE Tasks
      SET
        title = ISNULL(@title, title),
        description = ISNULL(@description, description),
        completed = ISNULL(@completed, completed)
      OUTPUT INSERTED.*
      WHERE id = @id
    `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: "Task not found" });
    }

    res.json(result.recordset[0]);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});