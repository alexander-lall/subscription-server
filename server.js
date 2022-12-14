import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import { readdirSync } from 'fs';

const morgan = require('morgan');
require('dotenv').config();

const app = express();

// db
mongoose.connect(process.env.DATABASE, {})
    .then(() => console.log("DB connected"))
    .catch((error) => console.log("DB Connection Error => ", error));

// middleware
app.use(express.json({ limit: '5MB' }));
app.use(cors({ origin: [process.env.CLIENT_URL] }));

// autoload routes
readdirSync('./routes').map((route) => app.use('/api', require(`./routes/${route}`)))

// listen
const port = process.env.PORT || 8000;
app.listen(port, () => console.log(`Server is running on port ${port}`));