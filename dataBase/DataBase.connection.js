import mongoose from "mongoose";

const DataBaseConnection = async () =>{
  await mongoose.connect('mongodb://127.0.0.1:27017/onlineStoreProject').then(() => {
        console.log("DataBase Connected");
    }).catch((err) => {
        console.log("DataBase Connection Error", err);})
    };


    export default DataBaseConnection;