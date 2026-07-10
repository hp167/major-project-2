const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("../models/User");

const router = express.Router();

router.post("/register", async (req, res) => {

try{

const {name,email,password}=req.body;

let user=await User.findOne({email});

if(user){

return res.status(400).json({
message:"User Already Exists"
});

}

user=new User({
name,
email,
password
});

const salt=await bcrypt.genSalt(10);

user.password=await bcrypt.hash(password,salt);

await user.save();

const payload={
user:{
id:user.id
}
};

jwt.sign(
payload,
process.env.JWT_SECRET,
{
expiresIn:"7d"
},
(err,token)=>{

res.json({token});

});

}catch(err){

res.status(500).send(err.message);

}

});

router.post("/login",async(req,res)=>{

try{

const {email,password}=req.body;

const user=await User.findOne({email});

if(!user){

return res.status(400).json({
message:"Invalid Credentials"
});

}

const isMatch=await bcrypt.compare(password,user.password);

if(!isMatch){

return res.status(400).json({
message:"Invalid Credentials"
});

}

const payload={
user:{
id:user.id
}
};

jwt.sign(
payload,
process.env.JWT_SECRET,
{
expiresIn:"7d"
},
(err,token)=>{

res.json({token});

});

}catch(err){

res.status(500).send(err.message);

}

});

module.exports=router;
