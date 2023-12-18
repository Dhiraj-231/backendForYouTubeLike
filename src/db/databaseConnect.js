import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config({ path: "../.env" });
export default async () => {
    try {
        await mongoose.connect(`${process.env.DATA_BASE_URL}`);
        console.log("Database is connected successfully");
    } catch (error) {
        console.log(error);
    }
};
