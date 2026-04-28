const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const { sql, connectDB, getPool } = require("./db");

require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// middleware
app.use(cors());
app.use(express.json());

// test route
app.get("/", (req, res) => {
  res.send("Backend is running");
});

// REGISTER
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const pool = getPool();

    if (!pool) {
      return res.status(500).json({ message: "Database not connected" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool
      .request()
      .input("username", sql.NVarChar, username)
      .input("password", sql.NVarChar, hashedPassword)
      .query(
        "INSERT INTO Users (username, password) VALUES (@username, @password)"
      );

    res.json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Registration failed" });
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const pool = getPool();

    if (!pool) {
      return res.status(500).json({ message: "Database not connected" });
    }

    const result = await pool
      .request()
      .input("username", sql.NVarChar, username)
      .query("SELECT * FROM Users WHERE username = @username");

    const user = result.recordset[0];

    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user.id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Login failed" });
  }
});

// AUTH MIDDLEWARE
const auth = (req, res, next) => {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ message: "No token" });
  }

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

// GET TASKS
app.get("/tasks", auth, async (req, res) => {
  try {
    const pool = getPool();

    const result = await pool.request().query("SELECT * FROM Tasks");

    res.json(result.recordset);
  } catch (error) {
    console.error("Get tasks error:", error);
    res.status(500).json({ message: "Failed to fetch tasks" });
  }
});

// ADD TASK
app.post("/tasks", auth, async (req, res) => {
  const { title, description } = req.body;

  try {
    const pool = getPool();

    const result = await pool
      .request()
      .input("title", sql.NVarChar, title)
      .input("description", sql.NVarChar, description)
      .query(
        "INSERT INTO Tasks (title, description, completed) OUTPUT INSERTED.* VALUES (@title, @description, 0)"
      );

    res.status(201).json(result.recordset[0]);
  } catch (error) {
    console.error("Add task error:", error);
    res.status(500).json({ message: "Failed to add task" });
  }
});

// UPDATE TASK
app.put("/tasks/:id", auth, async (req, res) => {
  const { id } = req.params;
  const { completed } = req.body;

  try {
    const pool = getPool();

    const result = await pool
      .request()
      .input("id", sql.Int, id)
      .input("completed", sql.Bit, completed)
      .query(
        "UPDATE Tasks SET completed = @completed OUTPUT INSERTED.* WHERE id = @id"
      );

    res.json(result.recordset[0]);
  } catch (error) {
    console.error("Update task error:", error);
    res.status(500).json({ message: "Failed to update task" });
  }
});

// DELETE TASK
app.delete("/tasks/:id", auth, async (req, res) => {
  const { id } = req.params;

  try {
    const pool = getPool();

    await pool
      .request()
      .input("id", sql.Int, id)
      .query("DELETE FROM Tasks WHERE id = @id");

    res.json({ message: "Task deleted successfully" });
  } catch (error) {
    console.error("Delete task error:", error);
    res.status(500).json({ message: "Failed to delete task" });
  }
});

// START SERVER AFTER DB CONNECTS
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});