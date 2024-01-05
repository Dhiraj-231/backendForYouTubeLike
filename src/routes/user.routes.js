import express from "express";
import {
    OtpGenerator,
    allUser,
    deleteprofile,
    getMyDetails,
    getUserDetails,
    loginUser,
    logout,
    refreshAccessToken,
    registerUser,
    updatePassword,
    updateUser,
    updateUserAvatar,
    updateUserCoverImage,
    verifyOtp,
} from "../controller/user.controller.js";
import { upload } from "../middleware/multer.middleware.js";
import { isAuth, localVariable } from "../middleware/isAuth.js";
const router = express.Router();

router.post(
    "/register",
    upload.fields([
        {
            name: "avtar",
            maxCount: 1,
        },
        {
            name: "coverImage",

            maxCount: 1,
        },
    ]),
    registerUser
);

router.post("/login", loginUser);
router.get("/logout", isAuth, logout);
router.patch("/updateProfile", isAuth, updateUser);
router.get("/refreshAccessTokens", refreshAccessToken);
router.get("/my", isAuth, getMyDetails);
router.get("/:id", getUserDetails);
router.get("/detail/all", isAuth, allUser);
router.patch("/updatePassword", isAuth, updatePassword);
router.delete("/delete", isAuth, deleteprofile);
router.get("/gen/otp", isAuth, localVariable, OtpGenerator);
router.get("/gen/verifyOtp", isAuth, localVariable, verifyOtp);
router.patch("/gen/v1/updateAvatar", isAuth, upload.single("avatar"), updateUserAvatar);
router.patch("/gen/v1/coverImage", isAuth, upload.single("coverImage"), updateUserCoverImage);

export default router;
