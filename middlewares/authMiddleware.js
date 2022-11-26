const User=require('../models/userModel')
const jwt=require('jsonwebtoken')
const asyncHandler=require('express-async-handler')
const isAuth=asyncHandler(async(req,res,next)=>
{
    let token;
    if(req.headers.authorization && req.headers.authorization.startsWith('Bearer'))
    {
        
        try {
            token=req.headers.authorization.split(' ')[1]
            //console.log(token)
            const decoded=jwt.verify(token,process.env.JWT_SECRET)
            //console.log(decoded)
            req.user=await User.findById(decoded.id).select('-password')
            next()
        } catch (error) {
            res.status(401).send('Not authorized token')
        }
        console.log(token)
        
    }
    if(!token)
        {
            console.log(token)
            res.status(401).send('Not authorized token')
        }
})

const isAdmin=asyncHandler(async(req,res,next)=>
{
   if(req.user && req.user.isAdmin)
   {
       next()
   }
   else return res.status(401).send("You are not an admin")
})

module.exports={isAuth,isAdmin}