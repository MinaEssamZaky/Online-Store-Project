import { AppError } from "../Utils/AppError.js"
export const handleError = (fn)=>{
     return (req,res,next)=>{
        fn(req,res,next).catch(err=> next (new AppError (err,401)))
     }
}