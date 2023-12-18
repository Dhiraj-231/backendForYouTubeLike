import { v2 as cloudinary } from "cloudinary";
import fs from "fs";
import dotenv from "dotenv";
dotenv.config();

cloudinary.config({
    cloud_name: process.env.CLOUD_NAME,
    api_key: process.env.API_KEY,
    api_secret: process.env.API_SECRET
});
const uploadOnCloudinary = async (localfilePath) => {
    try {
        if (!localfilePath) return "Error";
        //upload the file in the cloudinary
        const response = await cloudinary.uploader.upload(localfilePath, {
            resource_type: "auto"
        });
        fs.unlinkSync(localfilePath);
        return response;
    } catch (error) {
        fs.unlinkSync(localfilePath); // remove the locally save temporary file as the uploading gets failed
        return error;
    }

}

export default uploadOnCloudinary;