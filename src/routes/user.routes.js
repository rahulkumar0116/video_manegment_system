import { Router } from "express";
import { loginUser, logoutUser, registerUser,refreshAccessToken, ChangeCurrentPassword, getCurrentUser, updatedUserDetails, UpdateUserAvatar, UpdateUserCoverImage, getUserChannelProfile, getWatchHistory} from "../controllers/user.controller.js";
import {upload} from "../middlewares/multer.middlewares.js"
import { verifyJWT } from "../middlewares/auth.middlewares.js";

const router = Router()

router.route("/register").post(
    upload.fields([
        {
            name: "avatar",
            maxCount:1
        },
        {
            name: "coverImage",
            maxCount: 1
        }
    ]),
    registerUser)  
router.route("/login").post(loginUser)

//secured router
router.route("/logout").post(verifyJWT, logoutUser)
router.route("/refresh-token").post(refreshAccessToken)
router.route("/change-password").post(verifyJWT, ChangeCurrentPassword)
router.route("/current-user").get(verifyJWT,getCurrentUser)
router.route("/upadte-account-details").patch(verifyJWT,updatedUserDetails)
router.route("/avatar").patch(verifyJWT,upload.single("avatar"),UpdateUserAvatar)
router.route("/cover-image").patch(verifyJWT,upload.single("/coverImage"),UpdateUserCoverImage)
router.route("/c/:username").get(verifyJWT,getUserChannelProfile)
router.route("/history").get(verifyJWT,getWatchHistory)


export default router;