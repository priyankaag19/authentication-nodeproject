require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const userRoutes = require('./userRoutes');

const app = express();
app.use(bodyParser.json());

app.use('/user', userRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
