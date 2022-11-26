const express=require('express')
const dotenv=require('dotenv')
const cors=require('cors')
const { v4: uuidv4 } = require('uuid')
const bcrypt=require('bcrypt')
const multer=require('multer')
const mongoose=require('mongoose')
const Member=require('./models/memberModel')
const path = require('path');
const jwt=require('jsonwebtoken')
const User=require('./models/userModel')
const {isAuth}=require('./middlewares/authMiddleware')
const PORT=process.env.port||5000;
dotenv.config()

const app=express()
//app.use(express.static(path.join(__dirname,'/public')));
app.use(express.json())


mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
.then(()=>console.log('mongoose is connected'))
.catch((err)=>console.log(err))

app.use(cors())



const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null,'public/uploads');
    },
    filename: function(req, file, cb) {   
        cb(null, uuidv4() + '-' + Date.now()+path.extname(file.originalname));
    }
});

const upload = multer({ storage });


///routes

app.post('/login',async(req,res)=>{
   const {email,password}=req.body;
    
    const user=await User.findOne({email});
    if(!user)
    {
        res.status(401).send('This email is not registered');
    }
    else
    {
        const isMatched= await bcrypt.compare(password,user.password);
        if(isMatched)
        {
            const generatedToken=jwt.sign({id:user._id},"very secret",{
                expiresIn:'10d'
            })
            res.json({
              _id:user._id,
              name:user.name,
              email:user.email,
              isAdmin:user.isAdmin,
              token:generatedToken
            })
        }
        else
        {
            return res.status(401).send('Email or password is wrong');
        }
    } 


}) 

app.get('/api/members',async(req,res)=>{
   try {
    const members=await Member.find({})
    return res.status(200).send(members)
   } catch (error) {
    return res.status(401).json({message:error})
   }
})

app.get('/api/members/:name/:id',async(req,res)=>{
   console.log(req.params)
   try {
    const member=await Member.findOne({_id:req.params.id,name:req.params.name})
   if(member)
   return res.status(200).send(member)
   else return res.status(404).send("not found")
   } catch (error) {
     return res.status(401).json({message:error})
   }
})

app.get('/api/editMember/:id',isAuth,async(req,res)=>{
    console.log(req.params)
     await Member.findOne({_id:req.params.id})
     .then(member=>res.status(200).send({member,success:true}))
     .catch(err=>res.status(404).send({message:"member not found",success:false}))
 })

 app.put('/api/editMember/:id',upload.single('image'),isAuth,async(req,res)=>{
    
    console.log(req.body)
    console.log(req.file)

    try{
        const member=await Member.findById(req.params.id)
        if(member)
        {
            const {name,email,phone,field_of_interest,description}=req.body;
            let imagePath='';
            if (req.file)
             imagePath = String('/' + req.file.destination.split('/').slice(1) + '/' + req.file.filename);
            else  imagePath = member.profileImg

            if(!(name==="") && !(email==="") && !(phone==="")){
                const isMemberExist=await Member.findOne({email});
            if(isMemberExist && (email!==member.email))
            {
               return res.status(401).send({message:'This member is already registered',success:false});
            }
            else{
            member.name=req.body.name||member.name
            member.email=req.body.email||member.email
            member.phone=req.body.phone||member.phone
            member.profileImg = imagePath
            member.field_of_interest=req.body.field_of_interest||member.field_of_interest
            member.description=req.body.description||member.description
            const updatedMember=await member.save();
            return res.status(200).send({member:updatedMember,success:true})
            }
        }
        else{
            return res.status(401).send({message:'* fields are required',success:false});
        }
        }
        else{
            return res.status(401).send({message:'Member not found',success:false});
        }
    }
    catch(error){
        console.log(error)
        return res.status(500).send({message:'Server error',success:false});
    }  
 })


app.post('/api/members',isAuth,async(req,res)=>
{

    console.log(req.body)
   const {name,email,phone,field_of_interest,jobs,description}=req.body;
  
    if(!(name==="") && !(email==="") && !(phone==="")){
        const isMemberExist=await Member.findOne({email});
    if(isMemberExist)
    {
       return res.status(401).send({message:'This user is already registered',success:false});
    }
    else{
    //const hashedPassword=await bcrypt.hash(password,10);
    const newMember=new Member({
    name,
    email,
    phone,
    field_of_interest,
    jobs,
    description
    });
     await newMember.save()
    .then(member=>{
        return res.status(200).send({member,success:true})
    })
    .catch(err=>{
        return res.status(500).send({message:'Server error',success:false});
    }); 
}  
    }
    else{
        return res.status(401).send({message:'* fields are required',success:false});
    }
})


app.put('/api/jobs/:id',isAuth,async(req,res)=>
{

    console.log(req.body)
   
  
   try{
    const member=await Member.findById(req.params.id)
    if(member)
    {
        const {company,startDate,endDate,designation,jobDescription}=req.body;
        const tempJobs=member.jobs;
        tempJobs.push({...req.body});
        member.jobs=tempJobs;
        const updatedMember=await member.save();
        console.log("updated")
        console.log(updatedMember)
        return res.status(200).send({member:updatedMember,success:true})
    
    }
    else{
        return res.status(401).send({message:'Member not found',success:false});
    }
}
catch(error){
    console.log(error)
    return res.status(500).send({message:'Server error',success:false});
}  
   
})


app.get('/api/deleteMember/:id',isAuth,async(req,res)=>{
    try{
        const deletedMember=await Member.findByIdAndRemove(req.params.id)
       return res.status(200).send(deletedMember)
        }
        catch(error){
           return res.status(401).send('User not found')
        }
})

app.use(express.static(path.join(__dirname, "./client/build")));
app.get("*", function (_, res) {
  res.sendFile(
    path.join(__dirname, "./client/build/index.html"),
    function (err) {
      res.status(500).send(err);
    }
  );
});

app.listen(PORT,(err)=>
{
    if(err) console.log(err)
    else console.log(`Server is running at ${PORT}`)
})