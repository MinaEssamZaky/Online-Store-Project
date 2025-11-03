import express from 'express';
import DataBaseConnection from './dataBase/DataBase.connection.js';
import { AppError } from './src/Utils/AppError.js';
import dotenv from "dotenv"
import userRoutes from './src/modules/User/user.routes.js';

dotenv.config()

const app = express();
const PORT = process.env.SERVER || 3000;
 
DataBaseConnection();
app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.use(express.json());
app.use('/api/v1/users',userRoutes);

app.use((req,res,next)=>{
    next (new AppError("URL Not Found !",404))
})

app.use((err,req,res,next)=>{
    console.error(err.stack);
    res.status(err.statusCode).json({message:err.message,stack:err.stack})
})

app.listen(PORT, () => {
    console.log(`Server is running on Port:${PORT}`);
});



