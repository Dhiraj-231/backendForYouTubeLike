import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import uploadOnCloudinary from "../utils/cloudinary.js";
import bcrypt, { compareSync } from "bcrypt";
import otpGenerator from "otp-generator";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();
const generateAccessAndRefereshToken = async (userId) => {
    const user = await User.findById(userId)
    const accessToken = user.generateAccessToken()
    const refreshToken = user.generateRefreshToken()
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false })

    return { accessToken, refreshToken }

}
export const registerUser = async (req, res) => {
    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res

    try {
        const { username, email, fullname, password } = req.body;
        if (
            [username, email, fullname, password].some(
                (field) => field?.trim() === ""
            )
        ) {
            throw new ApiError(400, "All field is required..");
        }
        const existUser = await User.findOne({
            $or: [{ username }, { email }],
        });
        if (existUser) {
            throw new ApiError(409, "User already existed..");
        }
        const avatarLocalPath = req.files?.avtar[0]?.path;
        let coverImageLocalPath;
        if (
            req.files &&
            Array.isArray(req.files.coverImage) &&
            req.files.coverImage.length > 0
        ) {
            coverImageLocalPath = req.files.coverImage[0].path;
        }
        if (!avatarLocalPath) {
            throw new ApiError(400, "Avatar file is required");
        }
        const avatar = await uploadOnCloudinary(avatarLocalPath);
        const coverImage = await uploadOnCloudinary(coverImageLocalPath);
        if (!avatar) {
            throw new ApiError(400, "Avatar file is required");
        }
        const user = await User.create({
            fullname,
            username: username.toLowerCase(),
            password,
            email,
            avtar: avatar.url,
            coverImage: coverImage?.url || "",
        });
        const createdUser = await User.findById(user._id).select(
            "-password -refreshToken"
        );
        if (!createdUser) {
            throw new ApiError(500, "Something went wrong while register user");
        }
        res.status(201).json({
            success: true,
            createdUser,
            message: "Okay get it",
        });
    } catch (error) {
        res.status(404).json({
            success: false,
            message: error.message,
        });
    }
};
export const loginUser = async (req, res) => {
    // req body -> data
    //username or email
    //find the user
    // password check
    // access token and referesh token
    // send cookies
    try {
        const { email, username, password } = req.body;
        if (!username && !email) throw new ApiError(404, "username or email is required");
        const user = await User.findOne({
            $or: [{ username }, { email }]
        }).select("+password");
        if (!user) throw new ApiError(404, "User not exist");
        const matchPassword = await user.isPasswordCorrect(password, user.password);
        if (!matchPassword) throw new ApiError(401, "Wrong password or username");
        const { accessToken, refreshToken } = await generateAccessAndRefereshToken(user._id);
        res
            .status(200)
            .cookie("Accesstoken", accessToken, {
                httpOnly: true,
                secure: true

            }).cookie("RefreshToken", refreshToken, {
                httpOnly: true,
                secure: true
            })
            .json({
                success: true,
                message: "login successfully",
            });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
};

export const logout = async (req, res) => {
    const user = await User.findById(req.user._id).select("+refreshToken");
    user.refreshToken = undefined;
    await user.save({ validateBeforeSave: false })

    res
        .status(200)
        .clearCookie("Accesstoken", { httpOnly: true })
        .clearCookie("RefreshToken", { httpOnly: true })
        .json({
            success: true,
            message: "Logout successfully",
        });
};

export const refreshAccessToken = async (req, res) => {
    try {
        const incomingRefreshToken = req.cookies.RefreshToken || req.body.RefreshToken;
        if (!incomingRefreshToken) throw new ApiError(401, "unauthorized Access");
        const decode = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
        const user = await User.findById(decode._id).select("+refreshToken");
        if (incomingRefreshToken !== user.refreshToken) throw new ApiError(401, "Refresh token is invalid");

        const { accessToken, refreshToken } = await generateAccessAndRefereshToken(user._id);
        res
            .status(200)
            .cookie("Accesstoken", accessToken, {
                httpOnly: true,
                secure: true

            }).cookie("RefreshToken", refreshToken, {
                httpOnly: true,
                secure: true
            })
            .json({
                success: true,
                accessToken, refreshToken,
                message: "Access token refresh successfully",
            });
    } catch (error) {
        res.status(400).json({
            success: false,
            message: error.message
        })
    }
}

export const updateUser = async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        const { username, email, fullname } = req.body;
        if (!username || !email || !fullname)
            throw new ApiError(400, "Please Provide username,email,fullname or one");
        await user.updateOne({
            username,
            email,
            fullname,
        });

        res.status(200).json({
            success: true,
            message: "Profile updated successfully",
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
};

export const getMyDetails = async (req, res) => {
    try {
        res.status(200).json({
            success: true,
            message: "Your profile details",
            user: req.user,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
};

export const getUserDetails = async (req, res) => {
    try {
        const { id } = req.params;
        const user = await User.findById({ _id: id });
        res.status(200).json({
            success: true,
            message: "Other user details",
            user,
        });
    } catch (error) {
        res.status(400).json({
            success: false,
            message: error.message,
        });
    }
};
export const allUser = async (req, res) => {
    try {
        const user = await User.find({});
        res.status(200).json({
            success: true,
            message: "All user details",
            user,
        });
    } catch (error) {
        res.status(400).json({
            success: false,
            message: error.message,
        });
    }
};
export const updatePassword = async (req, res) => {
    try {
        const user = await User.findById({ _id: req.user._id }).select("+password");
        const { oldpassword, newpassword } = req.body;
        if (!oldpassword || !newpassword) {
            throw new ApiError(404, "Please enter old and new password.");
        }
        const match = await user.isPasswordCorrect(oldpassword, user.password);
        if (!match) throw new ApiError(404, "Wrong password.");
        const hashPassword = await bcrypt.hash(newpassword, 10);
        await user.updateOne({
            password: hashPassword,
        });
        res.status(200).json({
            success: true,
            message: "Password updated successfully",
        });
    } catch (error) {
        res.status(400).json({
            success: false,
            message: error.message,
        });
    }
};
export const deleteprofile = async (req, res) => {
    try {
        await User.findOneAndDelete({ _id: req.user._id });
        req.user = null;
        res.status(200).json({
            success: true,
            message: "Deleted successfully.",
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
};
export const OtpGenerator = async (req, res) => {
    try {
        req.app.locals.OTP = await otpGenerator.generate(6, {
            upperCaseAlphabets: false,
            specialChars: false,
            lowerCaseAlphabets: false,
        });
        res.status(200).json({
            success: true,
            code: req.app.locals.OTP,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
};
export const verifyOtp = async (req, res) => {
    try {
        const { code } = req.query;
        if (parseInt(req.app.locals.OTP) === parseInt(code)) {
            req.app.locals.OTP = null;
            req.app.locals.resetSession = true;
            return res.status(200).json({
                success: true,
                message: "Verified successfully..!!",
            });
        }
        res.status(400).json({
            success: false,
            message: "Wrong otp..",
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
};
export const updateUserAvatar = async (req, res) => {
    try {
        const avatarLocalPath = req.file?.path;
        if (!avatarLocalPath) throw new ApiError(400, "Avatar file must be passed");
        const avatar = await uploadOnCloudinary(avatarLocalPath);
        console.log(avatar.url)
        if (!avatar.url) throw new ApiError(400, "Error while uploading file");
        const user = await User.findByIdAndUpdate(req.user._id, { avtar: avatar.url });
        console.log("User");
        res.status(200).json({
            success: true,
            message: "Profile photo update successfull"
        })

    } catch (error) {
        res.status(400).json({
            success: false,
            message: error.message
        })

    }
}

export const updateUserCoverImage = async (req, res) => {
    try {
        const localCoverImage = req.file?.path;
        console.log(localCoverImage)
        if (!localCoverImage) throw new ApiError(400, "CoverIamge file must be passed");
        const coverImage = await uploadOnCloudinary(localCoverImage);
        console.log(coverImage.url);
        if (!coverImage.url) throw new ApiError(400, "Error while uploading file");
        const user = await User.findByIdAndUpdate(req.user._id, { coverImage: coverImage.url });
        res.status(200).json({
            success: true,
            message: "Cover image update successfull"
        })

    } catch (error) {
        res.status(400).json({
            success: false,
            message: error
        })

    }
}



export const createSession = async (req, res) => {
    if (req.user.locals.resetSession) {
        req.user.locals.resetSession = false;
        return res.status(201).json({
            success: true,
            message: "Access Granted",
        });
    }
    res.status(440).json({
        success: false,
        message: "Sesssion exipred! ",
    });
};

export const resetPassword = async (req, res) => {
    try {
        if (req.app.locals.resetSession) throw new ApiError(400, "Session expired");
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) throw new ApiError(400, "User not exist");
        const hashpassword = await bcrypt.hash(password, 10);
        await user.updateOne({ password: hashpassword });

        res.status(200).json({
            success: true,
            message: "Update successfully..",
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
};
