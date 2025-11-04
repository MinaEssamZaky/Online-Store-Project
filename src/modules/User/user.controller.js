import { userModel } from "../../../dataBase/models/user.model.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { AppError } from "../../Utils/AppError.js";
import { handleError } from "../../middleware/handleError.js";
import { sendMail } from "../../email/sendEmail.js";

export const signUp = handleError(async (req, res, next) => {
  const { firstName, lastName, email, password, phone, userType, businessName } = req.body;

  if (!email || !password) return next(new AppError("Email and password are required", 400));
  if (!firstName || !lastName) return next(new AppError("First and last name are required", 400));

  // Address parsing & validation
  let address = {};
  if (!req.body.address) {
    return next(new AppError("Address is required and must include street and city", 400));
  }
  try {
    address = (typeof req.body.address === "string") ? JSON.parse(req.body.address) : req.body.address;
  } catch (err) {
    return next(new AppError("Invalid address format", 400));
  }
  if (!address.street || !address.city) {
    return next(new AppError("Address must include street and city", 400));
  }

  // check existing email
  const existing = await userModel.findOne({ email });
  if (existing) return next(new AppError("Email already registered", 400));

  // userType checks
  if (userType === "storeOwner" || userType === "wholesaler") {
    if (!businessName) return next(new AppError("businessName is required for this userType", 400));
    if (!req.file) return next(new AppError("commercialRegister image is required for this userType", 400));
  }

  // hash password
  const saltRounds = Number.parseInt(process.env.SALT_ROUNDS || "10", 10) || 10;
  const hashed = await bcrypt.hash(password, saltRounds);

  // prepare payload
  const payload = {
    firstName,
    lastName,
    email,
    password: hashed,
    phone,
    address,
    userType,
    accountStatus: userType === "customer" ? "approved" : "pending",
    businessInfo: {}
  };

  if (businessName) payload.businessInfo.businessName = businessName;
  if (req.file) {
    // if using cloudinary, req.file may contain `path` or `secure_url` or `filename`
    // adapt to what your multer/cloudinary returns:
    payload.businessInfo.commercialRegister = req.file.path ? req.file.path.replace(/\\/g, "/") : (req.file.secure_url || req.file.filename || "");
  }

  // Create user first
  const user = await userModel.create(payload);

  // Create email verification token (use user id or email)
  const tokenPayload = { id: user._id, email: user.email };
  const token = jwt.sign(tokenPayload, (process.env.TOKEN || "secret").toString().trim(), { expiresIn: "15m" });

  // Optionally: save verification token to user document (recommended)
  // await userModel.findByIdAndUpdate(user._id, { verifyToken: token, verifyTokenExpires: Date.now() + 15*60*1000 });

  // Send verification email — if it fails we catch and log but do not break user creation
  try {
    await sendMail(email, token);
  } catch (mailErr) {
    console.error("Failed to send verification email:", mailErr);
    // you may optionally update user doc to mark email not sent
  }

  // Prepare response (do NOT send hashed password or raw token in production)
  const responseData = {
    id: user._id,
    userType: user.userType,
    personalInfo: {
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      phone: user.phone,
      address: {
        street: user.address.street,
        city: user.address.city
      }
    },
    accountStatus: user.accountStatus
  };

  if (user.businessInfo && (user.businessInfo.businessName || user.businessInfo.commercialRegister)) {
    responseData.businessInfo = {
      businessName: user.businessInfo.businessName || "",
      commercialRegister: user.businessInfo.commercialRegister || ""
    };
  }

  return res.status(201).json({
    message: "User registered",
    Data: responseData,
  });
});

export const Update= handleError(async (req,res,next)=>{
    const {email ,phone,userType} = req.body
    const user = await userModel.findById(req.user._id)

        if (!user) {
                return next(new AppError("User not found",400));
    }

    if (email) {
        const existingUser = await userModel.findOne({ email });
        if(user.email == email||existingUser){
        return next(new AppError("Email already exists",400));
        }
        user.email = email;
    }

    if (phone) {
                const existingPhone = await userModel.findOne({ phone });
        if(user.phone == phone||existingPhone){
        return next(new AppError("Phone already exists",400));
        }
        user.phone = phone;
    }

      let address = {};
  if (!req.body.address) {
    return next(new AppError("Address is required and must include street and city", 400));
  }
  try {
    address = (typeof req.body.address === "string") ? JSON.parse(req.body.address) : req.body.address;
  } catch (e) {
    return next(new AppError("Invalid address format", 400));
  }

  if (!address.street || !address.city) {
    return next(new AppError("Address must include street and city", 400));
  }
  user.address = address;

    if(userType){
        user.userType = userType
    }

    const updatedUser = await user.save();
    return res.status(200).json({ message: 'Done', user: updatedUser });
})


export const signIn = handleError(async (req, res, next) => {
  const { email, password } = req.body; 
  const user = await userModel.findOne({ email  });
  if (!user) return next(new AppError("Invalid email", 401));
  const isMatch = bcrypt.compareSync(password, user.password);
  if (!isMatch) return next(new AppError("Invalid password", 401));
  if (!user.isVerify) {
        return next(new AppError("Please verify your email first", 401));
    }
  const token = jwt.sign(
    { id: user._id, email: user.email },
    (process.env.TOKEN || "secret").toString().trim(),
    { expiresIn: "7d" }
  );
  return res.status(200).json({
    message: "User signed in",
    userData:user,
    token
  });

})


export const VerifyEmail = handleError(async (req, res, next) => {
    const { token } = req.query;
    if (!token) {
        return next(new AppError("Token is required", 400));
    }
    const decoded = jwt.verify(token, process.env.TOKEN);
    const user = await userModel.findOne({ email: decoded.email });
    if (!user) {
        return next(new AppError("User not found", 404));
    }
    user.isVerify = true;
    await user.save();
    res.status(200).json({ message: "Email verified successfully" });
});

export const resendVerifyEmail = handleError(async (req, res, next) => {
    const { email } = req.body;
    const user = await userModel.findOne({ email });
    if (!user) {
        return next(new AppError("User not found", 404));
    }
    if (user.isVerify) {
        return next(new AppError("Email already verified", 400));
    }
    const emailToken = jwt.sign({ email }, process.env.TOKEN, { expiresIn: "3m" });
    await sendMail(email, emailToken);
    return res.status(200).json({ message: "Verification email resent successfully" });
});

    export const changePassword = handleError(async(req,res,next)=>{
            const {oldPassword,newPassword} = req.body
        const user = await userModel.findById(req.user._id)
            if(!user){
            return next(new AppError("you should be logged in to change your password",400));
            }
            if(!oldPassword || !newPassword){
                    return next(new AppError("please Enter old and new password",400));
            }
            const match = bcrypt.compareSync(oldPassword,user.password)
            if(!match){
                            return next(new AppError("old password is not correct",400));
            }
            if(oldPassword === newPassword){
                    return next(new AppError("new password should be different from old password",400));
            }
            const saltRounds = parseInt(process.env.NEW_SALT_ROUNDS || "8");
            const hashedPassword = bcrypt.hashSync(newPassword,saltRounds)
            user.password = hashedPassword
            const updatedUser = await user.save()           
                return res.status(200).json({message:"password changed",user:updatedUser})
        })

// Forgot Password Waiting for sendMail function implementation        
export const forgotPassword = handleError(async (req, res, next) => {
  const { email } = req.body;

  const user = await userModel.findOne({ email });
  if (!user) {
    return next(new AppError("User not found", 404));
  }

  const resetToken = jwt.sign({ id: user._id }, process.env.TOKEN, { expiresIn: "10m" });

  const resetLink = `${process.env.CLIENT_URL}/resetPassword/${resetToken}`;
 await sendMail(email, resetToken, resetLink); 

  res.status(200).json({ message: "Reset link sent to email" });
});


export const resetPassword = handleError(async (req, res, next) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.TOKEN);
    const user = await userModel.findById(decoded.id);
    if (!user) return next(new AppError("User not found", 404));

    const salt = parseInt(process.env.SALT_ROUNDS);
    const hashed = bcrypt.hashSync(newPassword, salt);
    user.password = hashed;
    await user.save();

    res.status(200).json({ message: "Password reset successfully" });
  } catch (err) {
    return next(new AppError("Invalid or expired token", 400));
  }
});



export const deleteUserById = handleError(async (req, res, next) => {
  if (req.user.role !== 'Admin') {
    return next(new AppError("Access Denied", 403));
  }

  const targetUserId = req.params.id;
  const user = await userModel.findById(targetUserId);
  if (!user) {
    return next(new AppError("User not found", 404));
  }

  await userModel.findByIdAndDelete(targetUserId);
  return res.status(200).json({ message: "User Deleted Successfully" });
});



export const GitAllUsers = handleError(async (req, res, next) => {
    if (req.user.userType !== 'Admin' ) {
        return next(new AppError("Access Denied", 403));
    }
    const users = await userModel.find({ userType: 'customer' });
    return res.status(200).json({ message: "All Users", users });

});


export const GitAllStoreOwner = handleError(async (req, res, next) => {
    const storeOwner = await userModel.find({ userType: 'storeOwner' });
    return res.status(200).json({ message: "All storeOwner", storeOwner });
});

export const GitAllWholesaler = handleError(async (req, res, next) => {
    const wholesaler = await userModel.find({ userType: 'wholesaler' });
    return res.status(200).json({ message: "All wholesaler", wholesaler });
});


export const GitUserById = handleError(async (req, res, next) => {
    const userId = req.params.id;
    const user = await userModel.findById(userId);  
    if (!user) {
        return next(new AppError("User not found", 404));
    }
    return res.status(200).json({ message: "User Data", user });
}); 

export const approveUserAccount = handleError(async (req, res, next) => {
    if (req.user.userType !== 'Admin') {
        return next(new AppError("Access Denied", 403));
    }
    const userId = req.params.id;
    const user = await userModel.findById(userId);
    if (!user) {
        return next(new AppError("User not found", 404));
    }
    user.accountStatus = 'approved';
    await user.save();
    return res.status(200).json({ message: "User account approved", user });
});

export const rejectUserAccount = handleError(async (req, res, next) => {
    if (req.user.userType !== 'Admin') {
        return next(new AppError("Access Denied", 403));
    }       
    const userId = req.params.id;
    const user = await userModel.findById(userId);
    if (!user) {
        return next(new AppError("User not found", 404));
    }   
    user.accountStatus = 'rejected';
    await user.save();
    return res.status(200).json({ message: "User account rejected", user });
});
