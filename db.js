const sql = require("mssql");

const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  options: {
    encrypt: true,
    trustServerCertificate: false,
  },
};

const connectDB = async () => {
  try {
    await sql.connect(config);
    console.log("Connected to Azure SQL");
  } catch (err) {
    console.error("DB Connection Error:", err);
  }
};

module.exports = { sql, connectDB };