const express = require("express");
const cors = require("cors");
const errorHandler = require("./middleware/errorHandler");
const authRouter = require("./routes/authRouter");
const dotenv = require("dotenv")
const path = require("path")

const app = express();


//path join
dotenv.config({path:path.join(__dirname,'config','.env')})



// Middleware to parse JSON
app.use(express.json());
app.use(cors());

// Routers
app.use("/api/v1/auth", authRouter);

// Error handling middleware
app.use(errorHandler);


module.exports = app
