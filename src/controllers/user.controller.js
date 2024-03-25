import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import {User} from "../models/user.model.js"
import { uploadOnCloud } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"
import mongoose from "mongoose";

// below no need of asyncHandler since we are not handling any web request
const generateAccessAndRefreshTokens = async(userId) => {
    try{
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        // adding value in an object (object -> user)
        user.refreshToken = refreshToken


        await user.save({validateBeforeSave: false}) 
        // (above) here mongoDB properties for validation kick in which will need the required field (eg->pw) in saving the object
        // so to avoid the validations mentioned in model and directly update the needful (here refresh tokens)
        // so => {validateBeforeSave: false}
        // with this, it will skip the checks since we dont need them now, we just need to update one field 
        
        return {accessToken, refreshToken}

    }
    catch(error){
        throw new ApiError(500, "something went wrong while generating tokens")
    }
}


// asynchandler is made by us. it takes a function as a parameter
const registerUser = asyncHandler( async (req, res) => {

    //get user details from frontend
    //validation
    //check if user already exists through a parameter: user, email,etc
    //check for images, check for avatar
    //upload them to cloudinary, avatar
    //create an object - create entry in db
    // remove pw and refresh token field from response
    // check for user creation
    // return res 

    const {fullName, email, username, password} = req.body
    // console.log("email : ", email);

    // if(fullName===""){
    //     throw new ApiError(400, "full name is required");
    // }

    // BETTER APPROACH : (instead of separate if blocks for each mandatory field)

    if(
        // some like map
        [fullName, email, username, password].some((field) => field?.trim() ==="") //means even after trimming its empty)
    ){
        throw new ApiError(400, "all fields are required")
    }

    const existingUser = await User.findOne({
        $or: [{username}, {email}] //if any of these found 
    })

    if(existingUser){
        throw new ApiError(409, "user with same credentials exists ")
    }
    console.log(req.files);

    // Like req.body, multer gives req.files
    // ? means if not null
    // this whole will return the first property's path of image
    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if(!avatarLocalPath){
        throw new ApiError(400, "avatar image required")
    }

    const avatar = await uploadOnCloud(avatarLocalPath)
    const coverImage = await uploadOnCloud(coverImageLocalPath)

    if(!avatar){
        throw new ApiError(400, "avatar image required")
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    // to check if user was actually created and remove pw and refresh tokens
    // select -> accepts string , with minus sign mention things to remove
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )
    if(!createdUser){
        throw new ApiError(500, "something went wrong while creating user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered successfully")
    )



    // res.status(200).json({
    //     message: "chai and code"
    // })
})


const loginUser = asyncHandler(async(req, res) => {
    // req body -> data
    // username / email
    // find user
    // if not exists -> throw error
    // else pw check
    // generate access and refresh tokens 
    // send cookies

    const {email, username, password} = req.body;
    console.log(email)
    if(!username && !email){
        throw new ApiError(400, "username or email required")
    }
    const user = await User.findOne({
        // or takes array 
        $or: [{username}, {email}]
    })

    if(!user){
        throw new ApiError(404, "user does not exist")
    }
    const isPwValid= await user.isPasswordCorrect(password);

    if(!isPwValid){
        throw new ApiError(401, "password incorrect. invalid user credentials")
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id)

    // below -> loggedInUser created cause above user does not have both tokens in its scope 
    // since saving of token happened after the creation of user*
    // instance loggedInUser has tokens

    const loggedInUser = await User.findById(user._id)
    .select("-password -refreshToken")

    // COOKIES 
    const options = {
        // without below 2 fields, the cookies can be modified by anyone from frontend
        // with these -> only modified by server
        httpOnly: true,
        secure: true
    }

    // with cookie parser : 
    return res.status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            //status
            200,
            //data
            {
                user: loggedInUser, accessToken, refreshToken
            },
            //message
            "User logged in successfully"
            //status code will be managed automatically
        )
    )
})

const logoutUser = asyncHandler(async(req, res) => {
    // we cant find user by id here which we need cause we dont have access to it via email or anything unlinke login
    // obviously we wont ask the user to enter email to logout 
    // so we will design our own middleware for the same

    // now we get access to req.user via verifyJWT middleware so we can access _id too

    await User.findByIdAndUpdate(
        req.user._id,
        {
            // $set: {
            //     refreshToken: undefined
            // }

            // whatever field to unset , put 1
            $unset: {
                refreshToken: 1
            }
        },
        {
            new: true
        }
    )

    //cookies
    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out"))

})

const refreshAccessToken = asyncHandler(async(req, res)=>{
    const incomingRefreshToken = req.cookie.refreshToken || req.body.refreshToken;

    if(!incomingRefreshToken){
        throw new ApiError(401, "Unauthorized request")
    }

    try{
        const decodedToken = jwt.verify(
        incomingRefreshToken,
        process.env.REFRESH_TOKEN_SECRET
    )

    const user = await User.findById(decodedToken?._id)

    if(!user){
        throw new ApiError(401, "invalid refresh token")
    }

    //now matching whether the ref token sent by user as req (incoming..) and ref token in user is same
    // then only we can give access token

    if(incomingRefreshToken!==user?.refreshToken){
        throw new ApiError(401, "refresh token is expired or used")
    }

    //now generating tokens since everything ok (matched)

    const options={
        httpOnly: true,
        secure: true
    }

    const {accessToken, newRefreshToken} = await generateAccessAndRefreshTokens(user._id)

    return res.status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", newRefreshToken, options).json(
        new ApiResponse(
            200,
            {accessToken, refreshToken:newRefreshToken},
            "Access token refreshed"
        )
    )
    }catch(error){
        throw new ApiError(401, error?.message || "invalid refresh token")
    }
})

const changeCurrentPassword = asyncHandler(async(req, res) => {
    const {oldpw, newpw} = req.body;

    const user = await User.findById(req.user?._id)
    
    const isPasswordCorrect = await user.isPasswordCorrect(oldpw)

    if(!isPasswordCorrect){
        throw new ApiError(400, "old password incorrect. enter valid one")
    }

    user.password = newpw
    await user.save({validateBeforeSave: false})   // pre hook will be called which will hash this pw

    return res.status(200).json(
        new ApiResponse(200, {}, "password updated successfully")
    )
})

const getCurrentUser = asyncHandler(async(req, res)=>{
    return res.status(200)
    .json(
        new ApiResponse(200, req.user, "current user fetched successfully")
    )
})

const updateAccountDetails = asyncHandler( async(req, res)=> {
    const {fullName, email} = req.body

    if(!fullName || !email){
        throw new ApiError(400, "all fields required")
    }
    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,
                email
            }
        },
        {new: true}    // info after update return via this
    ).select("-password")

    return res.status(200)
    .json(
        new ApiResponse(200, user, "account details updated")
    )
})

const updateUserAvatar = asyncHandler( async(req, res) => {
    //file* not files* here since earlier we required array of files - avatar, coverimg
    // but here we require only one file as request

    //write *avatar* in key of form data in postman because this is the field name
    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath){
        throw new ApiError(400, "avatar not found")
    }

    const avatar = await uploadOnCloud(avatarLocalPath);

    if(!avatar.url){
        throw new ApiError(400, "error while uploading new avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                avatar: avatar.url
            }
        },
        {new: true}
    ).select("-password")

    return res.status(200)
    .json(
        new ApiResponse(
            200,
            user,
            "avatar updated"
        )
    )

})

const updateUserCoverImage = asyncHandler( async(req, res) => {
    //file* not files* here since earlier we required array of files - avatar, coverimg
    // but here we require only one file as request
    const coverImageLocalPath = req.file?.path

    if(!coverImageLocalPath){
        throw new ApiError(400, "cover image not found")
    }

    const coverImage = await uploadOnCloud(coverImageLocalPath);

    if(!coverImage.url){
        throw new ApiError(400, "error while uploading new cover image")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage: coverImage.url
            }
        },
        {new: true}
    ).select("-password")

    return res.status(200)
    .json(
        new ApiResponse(
            200,
            user,
            "cover image updated"
        )
    )
})

const getUserChannelProfile = asyncHandler(async(req, res) => {
    const {username} = req.params

    if(!username?.trim()){
        throw new ApiError(400, "username is missing")
    }

    // directly applying aggregation pipelines

    const channel = await User.aggregate([
        //pipeline 1
        {
            // match the document having username that we acquired from req.params
            $match: {
                username: username?.toLowerCase()
            },
            // now we have that one document we needed
        },
            //  lookup for finding number of subscribers of that profile user
        {
            $lookup: {
                // remember we are in User table right now and accessing Subscriber table

                // from -> what i want to access
                from: "subscriptions",
                // stored as _id in User (local (user) name of the field on the basis of which joining)
                localField: "_id",
                // stored as channel in subscribers (foreign (subs) name of...)
                foreignField: "channel",
                // now we get the user with this id which have this channel => subscribers (save as*)
                as: "subscribers"
            },
        },
        // pipeline 2
        {
            // lookup for finding number of channels subscribed by profile user
            // for this -> we need to go to the user having this _id, which is subscriber
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            }
        },
        {
            // adding additional fields apart from existing ones
            $addFields: {
                subscribersCount: {
                    $size: "$subscribers"
                },
                channelsSubscribedToCount: {
                    $size: "$subscribedTo"
                },
                // is the profile subscribed by us
                isSubscribed:{
                    $cond:{
                        if:{
                            // if the user url is in the profile's subcribers* field's object (obj->subscriber (from model))
                            // $in sees in arrays and objects both, here obj.
                            $in: [req.user?._id, "$subscribers.subscriber"]
                        }, then : true,
                        else: false
                    }
                }
            }
        },

        // project -> giving selected things not all
        // put 1 infront of things i want to pass (like flag)
        {
            $project: {
                fullName: 1,
                username: 1,
                subscribersCount: 1,
                channelsSubscribedToCount: 1,
                isSubscribed: 1,
                avatar: 1,
                coverImage: 1,
                email: 1
            }
        }
    ])

    if(!channel?.length){
        throw new ApiError(404, "channel does not exist")
    }

    //getting first object only
    return res.status(200)
    .json(
        new ApiResponse(200, channel[0], "user channel fetched successfully")
    )
})

const getWatchHistory = asyncHandler( async(req, res) => {
    const user = await User.aggregate([
        {
            // normally we get whole string of ObjectId("6738826629") and mongoose takes out id from it 
            // but in aggregation: this handling is not done and we receive whole string
            // hence we need to convert or fetch actual id from this string
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup:{
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                //subpipelines :
                pipeline: [
                    {
                        $lookup: {
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            // further pipeline to fetch only required fields out of user field (owner) we accessed
                            // hence using $project
                            pipeline: [
                                {
                                    $project: {
                                        fullName: 1,
                                        username: 1,
                                        avatar: 1
                                    }
                                }
                            ]
                        }
                    },
                    // 2nd pipeline for structure improvement of data received 
                    {
                        $addFields: {
                            owner: {
                                // taking out first value -> then -> taking out value from field ($owner)
                                $first: "$owner"
                            }
                        }
                    }
                ]
            }
        }
    ])
    return res.status(200).json(
        new ApiResponse(200, user[0].watchHistory, "watchHistory")
    )
})

export {
    registerUser, 
    loginUser, 
    logoutUser, 
    refreshAccessToken,
     changeCurrentPassword, 
     getCurrentUser,
     updateAccountDetails,
     updateUserAvatar,
     updateUserCoverImage,
     getUserChannelProfile,
     getWatchHistory
    }