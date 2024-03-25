// verifies if user there or not 

import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"
import {User} from "../models/user.model.js"

// res is not used here so we can write _ instead of res
export const verifyJWT = asyncHandler(async(req, _, next) => {
    try{
        // req has access to cookies because of cookie parser
    
    // we are checking if cookie is present or not even though we sent it in login
    // this is because there can be situations of mobile apps where user sending custom headers 
    // so we access header name  ->   which is mostly *Authorization* :

    // if we find bearer token (we dont need whole bearer tokn, only access tokens needed) 
    // -> so we replace it with ""

    const token = req.cookies?.accessToken || req.header
    ("Authorization")?.replace("Bearer", "")

    if(!token){
        throw new ApiError(401, "unauthorized request")
    }

    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)

    const user = await User.findById(decodedToken?._id).select("-password -refreshToken")

    if(!user){
        throw new ApiError(401, "invalid access token")
    }

    req.user = user;
    next()
    }catch(error){
        throw new ApiError(401, error?.message || "invalid access token")
    }
})