import { Router } from "express";
import { changeCurrentPassword, 
    getCurrentUser, 
    getUserChannelProfile, 
    getWatchHistory, 
    loginUser,
     logoutUser, 
     refreshAccessToken,
      registerUser, 
     updateAccountDetails, 
     updateUserAvatar,
      updateUserCoverImage } from "../controllers/user.controller.js";

import { verifyJWT } from "../middlewares/auth.middleware.js";
import {upload} from "../middlewares/multer.middleware.js"
const  router = Router();

router.route("/register").post(
    //adding middleware right before route (meet middleware just before reaching route)
    // fields -> since we require multiple fields . it accepts array
    upload.fields([
        //avatar
        {
            name: "avatar",   // give same name in frontend also 
            maxCount: 1
        },
        // cover image
        {
            name: "coverImage",
            maxCount: 1
        }
    ]),
    registerUser
    )
router.route("/login").post(loginUser)

//secured routes (sure that user is already logged in)

router.route("/logout").post(verifyJWT ,logoutUser)
//next written cause of such cases only where two methods are supposed to be carried out
// next tells that my work is done now you can move forward (can do with multiple middlewares)

router.route("/refresh-token").post(refreshAccessToken)

// applying verifyJWT whereever we need the user to be logged in to perform the following operation
router.route("/change-password").post(verifyJWT, changeCurrentPassword)

router.route("/current-user").get(verifyJWT, getCurrentUser)

//patch to update only required field else all will be updated with post
router.route("/update-account").patch(verifyJWT, updateAccountDetails)

// two middlewares used in order: fristly we need user to be logged in 
// and then only we can check for multer middleware
router.route("/avatar").patch(verifyJWT, upload.single("avatar"), updateUserAvatar)

router.route("cover-image").patch(verifyJWT, upload.single("coverImage"), updateUserCoverImage)

//use same name assigned with params in this controller function (username) with collon
router.route("/c/:username").get(verifyJWT, getUserChannelProfile)

router.route("/history").get(verifyJWT, getWatchHistory)


export default router;