import {asyncHandler} from "../utils/asyncHandler.js"
import {ApiError} from "../utils/ApiError.js"
import {User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import {ApiResponse} from "../utils/ApiResponse.js"
import jwt from "jsonwebtoken";
import mongoose from "mongoose"

const genrateAccessAndRefreshToken = async(userId)=>{
    try {
        const user = await User.findById(userId);
        const accessToken = user.genrateAccessToken()
        const refreshToken = user.genrateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({validateBeforeSave: false})
        return{accessToken, refreshToken}
    } catch (error) {
        throw new ApiError(500, "somthing went worng while genreting refersh and access token")
    }
}
const registerUser = asyncHandler(async (req, res)=>{
    //get user details from frontend
    //validation- not empty
    //check if user already exists: username email
    //check for images, check for avatar
    //upload them on cloudinary, avatar check
    //create user objects- create entry in db
    //remove password and refresh token from response
    //check for user creation
    //return register user

    const {fullName, email, username, password}= req.body
    // if (fullName === "") {
    //     throw new ApiError(400, "FullName is required")
    // }
    //aise hi sare field ko check kar shakte hai

    if (
        [fullName, email, username, password].some((field) => field?.trim()=== "")
    ) {
        throw new  ApiError(400, "All fields are required")
    }

    const existedUser = await User.findOne({
        $or: [{username}, {email}]
    })
    if (existedUser) {
        throw new ApiError(409, "username or email already in used")
    }
    const avatarLocalPath = req.files?.avatar[0]?.path;
    //const coverImageLocalPath = req.files?.coverImage[0]?.path;
    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length >0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);
    if (!avatar) {
        throw new ApiError(400, "Avatar file is required");
    }
    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )
    if (!createdUser) {
        throw new ApiError(500, "Somthing went worng while registering the user")
    }
    return res.status(201).json(
        new ApiResponse(200, createdUser, "user registred successfully")
    )
})
const loginUser = asyncHandler(async (req, res)=>{
    //req body -> data
    //get email or username from frontend
    //find user
    //get password from frontend
    //password check
    //access token or refresh token
    //send in cookies
    const {email, username, password} = req.body
    console.log(email)
    if (!username && !email) {
        throw new ApiError(400, "username or email is required")
    }

    const user = await User.findOne({
        $or: [{username},{email}]
    })
    if (!user) {
        throw new ApiError(400, "User does not exist")
    }
    const isPasswordValid = await user.isPasswordCorrect(password)
    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid user credentials")
    }

    const {accessToken, refreshToken} = await genrateAccessAndRefreshToken(user._id)
    const loggedInUser = await User.findById(user._id)
    .select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }
    return res.status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200,
            {
                user:loggedInUser, accessToken, refreshToken
            },
            "user logged in successfully"
        )
    )
})
const logoutUser = asyncHandler(async(req, res)=>{
    await User.findByIdAndUpdate(req.user._id,
    {
        $set:{
            refreshToken: undefined
        }
    },
    {
        new: true
    })

    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200,{},"User logged out"))
})
const refreshAccessToken = asyncHandler(async(req, res)=>{
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    if(!incomingRefreshToken){
        throw new ApiError(401, "unauthorized request")
    }
    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
        const user = await User.findById(decodedToken?._id)
        if (!user) {
            throw new ApiError(401, "Invalid refresh token")
        }
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token in expired or used")
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
        const {accessToken, newRefreshToken}= await genrateAccessAndRefreshToken(user._id)
        return res 
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("newRefreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200,
                {accessToken, refreshToken: newRefreshToken},
                "Access token refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }

})
const ChangeCurrentPassword = asyncHandler(async(req, res)=>{
    const{oldPassword,newPassword} = req.body
    const user = User.findById(req.user?._id)
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)
    if (!isPasswordCorrect) {
        throw new ApiError(400, "Invalid old password")
    }
    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res
    .status(200)
    .json(new ApiResponse(200),{},"Password change successfully")

})
const getCurrentUser = asyncHandler(async(req, res)=>{
    const user = User.findById(req.user?._id)
    return res.status(200)
    .json(200, user, "Current user fetched successfully")
})
const updatedUserDetails = asyncHandler(async(req, res)=>{
    const {fullName, email} = req.body
    if (!fullName || !email) {
        throw new ApiError(400,"full Name or email id is required")
    }
    const user = await User.findByIdAndUpdate(req.user?._id,
        {
            $set:{
                fullName:fullName,
                email:email
            }
        },
        {new:true}
        ).select("-password")

        return res
        .status(200)
        .json(new ApiResponse(200,user,"user details updated successfully"))
})
const UpdateUserAvatar = asyncHandler(async(req, res)=>{
    const avatarLocalPath = req.file?.path
    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is missing")
    }
    const avatar = uploadOnCloudinary(avatarLocalPath)
    if (!avatar.url) {
        throw new ApiError(400, "Error while uploading on avatar")
    }
    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                avatar: avatar.url
            }
        },
        {new:true}
        ).select("-password")

        return res
        .status(200)
        .json(
            new ApiResponse(200,user,"Avatar image updated")
            )
})
const UpdateUserCoverImage = asyncHandler(async(req, res)=>{
    const coverImageLocalPath = req.file?.path
    if (!coverImageLocalPath) {
        throw new ApiError(400, "Cover Image file is missing")
    }
    const coverImage = uploadOnCloudinary(coverImageLocalPath)
    if (!coverImage.url) {
        throw new ApiError(400, "Error while uploading on cover image")
    }
    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                coverImage: coverImage.url
            }
        },
        {new:true}
        ).select("-password")

        return res
        .status(200)
        .json(
            new ApiResponse(200,user,"cover image updated")
            )
})
const getUserChannelProfile = asyncHandler(async(req, res)=>{
    const {username} = req.params
    if (!username) {
        throw new ApiError(400,"Username is not found")
    }
    const channel = await User.aggregate([
        {
            $match:{
                username: username?.toLowerCase()
            }
        },
        {
            $lookup:{
                from:"subscriptions",
                localField:"_id",
                foreignField:"channel",
                as:"subscribers"
            }
        },
        {
            $lookup:{
                from:"subscriptions",
                localField:"_id",
                foreignField:"subscriber",
                as:"subscriberTo"
            }
        },
        {
            $addFields:{
                subscriberCount: {
                    $size:"$subscribers"
                },
                channelSubscriberedToCount:{
                        $size:"$subscriberTo"
                },
                isSubscribed:{
                    $cond:{
                        if: {$in:[req.user?._id,"$subscribers.subscriber"]},
                        then: true,
                        else:false
                    }
                }
            }
        },
        {
            $project:{
                fullName:1,
                username:1,
                subscriberCount:1,
                channelSubscriberedToCount:1,
                isSubscribed:1,
                avatar:1,
                email:1,
                coverImage:1
            }
        }
    ])
    if (!channel?.length) {
        throw new ApiError(400,"channel does not exist")
    }
    return res
    .status(200)
    .json(new ApiResponse(200, channel[0],"User channel fetched successfully" ))
})
const getWatchHistory = asyncHandler(async(req,res)=>{
    const user = await User.aggregate([
        {
            $match:{
                _id: new mongoose.Types.ObjectId(req.uesr?._id)
            },
        },
        {
            $lookup:{
                from:"Videos",
                localField:"watchHistory",
                foreignField:"_id",
                as:"WatchHistory",
                pipeline:[
                    {
                        $lookup: {
                            from:"users",
                            localField:"owner",
                            foreignField:"_id",
                            as:"owner",
                            pipeline:[
                                {
                                    $project:{
                                        fullName:1,
                                        username:1,
                                        avatar:1
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields:{
                            owner:{
                                $first: "$owner"
                            }
                        }
                    }
                ]
            }
        }
    ])
    return res
    .status(200)
    .json(new ApiResponse(200,user[0].watchHistory), "Watch history fetched successfully")
})
export {registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    ChangeCurrentPassword,
    getCurrentUser,
    UpdateUserAvatar,
    UpdateUserCoverImage,
    updatedUserDetails,
    getUserChannelProfile,
    getWatchHistory}