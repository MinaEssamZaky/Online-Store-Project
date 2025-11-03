import express from "express";
import { approveUserAccount, changePassword, deleteUserById, forgotPassword, GitAllStoreOwner, GitAllUsers, GitAllWholesaler, GitUserById, rejectUserAccount, resendVerifyEmail, resetPassword, signIn, signUp, Update, VerifyEmail } from "./user.controller.js";
import { upload } from "../../Utils/multer.js";
import { auth, authorizeRoles } from "../../middleware/auth.js";

const userRoutes = express.Router();

userRoutes.post("/signUp", upload.single("commercialRegister"), signUp);
userRoutes.post("/signIn", signIn);
userRoutes.put("/changePassword",auth(),changePassword)
userRoutes.post("/forgotPassword", auth(),forgotPassword)
userRoutes.post("/resetPassword/:token", resetPassword);
userRoutes.get("/verifyEmail", VerifyEmail)
userRoutes.post("/resendVerifyEmail",resendVerifyEmail)
userRoutes.put("/update",auth(),Update)
userRoutes.delete("/delete/:id",auth(),authorizeRoles("Admin"),deleteUserById)
userRoutes.get("/gitAllUsers",auth(),authorizeRoles("Admin"),GitAllUsers)
userRoutes.get("/GitAllStoreOwner",auth(),GitAllStoreOwner)
userRoutes.get("/GitAllWholesaler",auth(),GitAllWholesaler)
userRoutes.get("/GitUserById/:id",auth(),GitUserById)
userRoutes.patch("/approveUserAccount/:id", auth(), authorizeRoles("Admin"),approveUserAccount)
userRoutes.patch("/rejectUserAccount/:id", auth(), authorizeRoles("Admin"),rejectUserAccount)

export default userRoutes;
