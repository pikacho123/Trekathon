const mysql = require("mysql2/promise")
const db=mysql.createPool({
    host: 'localhost',        // Replace with your host
  user: 'root',    // Replace with your MySQL username
  password: 'saurabh123',// Replace with your MySQL password
  database: 'trekk' // Replace with your database name
})
module.exports = db;
