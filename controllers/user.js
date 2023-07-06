import { User } from "../models/user.js";
import bcrypt from "bcrypt";
import { sendCookie } from "../utils/features.js";
import ErrorHandler from "../middlewares/error.js";

export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select("+password");

    if (!user) return next(new ErrorHandler("Invalid Email or Password", 400)); 

    //password comparison
    const isMatch = await bcrypt.compare(password, user.password); 
    
    //if does not match
    if (!isMatch)
      return next(new ErrorHandler("Invalid Email or Password", 400));

    //if matches
    sendCookie(user, res, `Welcome back, ${user.name}`, 200);
  } catch (error) {
    next(error);
  }
};

export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    let user = await User.findOne({ email });

    if (user) return next(new ErrorHandler("User Already Exist", 400)); //already registered

    const hashedPassword = await bcrypt.hash(password, 10); //storing hashed password

    user = await User.create({ name, email, password: hashedPassword }); //create in DB

    sendCookie(user, res, "Registered Successfully", 201); //using feature.js
  } catch (error) {
    next(error);
  }
};

//isAuthenticated will run before this
export const getMyProfile = (req, res) => {
  res.status(200).json({
    success: true,
    user: req.user,
  });
};

export const logout = (req, res) => {
  res
    .status(200)
    .cookie("token", "", {
      expires: new Date(Date.now()),
      sameSite: process.env.NODE_ENV === "Develpoment" ? "lax" : "none",
      secure: process.env.NODE_ENV === "Develpoment" ? false : true,
    })
    .json({
      success: true,
      user: req.user,
    });
};
