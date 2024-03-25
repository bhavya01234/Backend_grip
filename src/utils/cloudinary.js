import {v2 as cloudinary} from "cloudinary"
import fs from "fs"

//sometimes the process.env isn't able to access the variables so you might need to 
//redefine the dotenv config inside the cloudinary file( just like we did at the top of index.js 

import dotenv from "dotenv"

dotenv.config({
    path: './.env'
})

// hence bug fixed

cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const uploadOnCloud = async(localFilePath) => {
    try{
        if(!localFilePath){
            return null;
        }
        const response =  await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto"
        })
        console.log("file has been uploaded on cloudinary", response.url);
        fs.unlinkSync(localFilePath)
        return response;
    }catch(error){
        // fs.unlink(localFilePath)
        fs.unlinkSync(localFilePath)
        
        // fs.unlink(localFilePath, (err) => {
        //     if (err) {
        //         console.error("Error deleting local file:", err);
        //     } else {
        //         console.log("Local file deleted successfully:", localFilePath);
        //     }
        // });
        console.error("Error uploading file to Cloudinary:", error);
        return null;
    }
}

export {uploadOnCloud}

// cloudinary.uploader.upload("https://upload.wikimedia.org/wikipedia/commons/a/ae/Olympic_flag.jpg",
//   { public_id: "olympic_flag" }, 
//   function(error, result) {console.log(result); });