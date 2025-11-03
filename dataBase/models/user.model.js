import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  phone: { type: String, required: true },
  address: {
    street: { type: String, required: true },
    city: { type: String, required: true }
  },
  accountStatus: {
    type: String,
    enum: ["pending", "approved", "rejected"],
    default: "pending"
  },
  userType: {
    type: String,
    enum: ["Admin", "storeOwner", "wholesaler", "customer"],
    default: "customer"
  },
  isVerify: { type: Boolean, default: false },

  // businessInfo مع الحقول المطلوبة فقط للمحلات والتجار بالجملة
  businessInfo: {
    businessName: {
      type: String,
      required: function () { return this.userType === "storeOwner" || this.userType === "wholesaler"; }
    },
    commercialRegister: {
      type: String,
      required: function () { return this.userType === "storeOwner" || this.userType === "wholesaler"; }
    }
  }
}, { timestamps: true });

export const userModel = mongoose.model("user", userSchema);
