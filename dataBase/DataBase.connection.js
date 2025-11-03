import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();


const DataBaseConnection = async () =>{
  await mongoose.connect(process.env.DB_URI).then(() => {
        console.log("DataBase Connected");
    }).catch((err) => {
        console.log("DataBase Connection Error", err);})
    };


    export default DataBaseConnection;