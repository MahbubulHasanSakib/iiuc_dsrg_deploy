const express=require('express')
const dotenv=require('dotenv')
const cors=require('cors')
const { v4: uuidv4 } = require('uuid')
const bcrypt=require('bcrypt')
const cloudinary=require('./utlis/cloudinary')
const multer=require('multer')
const mongoose=require('mongoose')
const Member=require('./models/memberModel')
const path = require('path');
const jwt=require('jsonwebtoken')
const User=require('./models/userModel')
const Committee=require('./models/committeeModel')
const Event=require('./models/eventModel')
const DsrgEvent=require('./models/dsrgEventModel')
const Blog=require('./models/blogModel')
const {isAuth,isAdmin}=require('./middlewares/authMiddleware')
const inMemoryStorage=multer.memoryStorage()
const { Readable } = require('stream');
const PORT=process.env.port||5000;
dotenv.config()

const app=express()
app.use(express.json())


mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
.then(()=>console.log('mongoose is connected'))
.catch((err)=>console.log(err))

app.use(cors())
app.use(express.static(path.join(__dirname,'/public')));
app.use(express.static(path.join(__dirname, './client/build')));

const upload = multer({ storage: inMemoryStorage });

const DatauriParser=require("datauri/parser");
const parser = new DatauriParser();


///routes


app.post('/login',async(req,res)=>{
   const {username,password}=req.body;
    
    const user=await User.findOne({username});
    if(!user)
    {
        res.status(401).send('This user is not registered');
    }
    else
    {
        const isMatched= await bcrypt.compare(password,user.password);
        if(isMatched)
        {
            const generatedToken=jwt.sign({id:user._id},process.env.JWT_SECRET,{
                expiresIn:'10d'
            })
            res.json({
              _id:user._id,
              username:user.username,
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

app.post('/register',async(req,res)=>{
   
        const {username,password}=req.body;
      
        const user=await User.findOne({username});
        if(user)
        {
           return res.status(401).send('This user is already registered');
        }
        else{
        const hashedPassword=await bcrypt.hash(password,10);
        const newuser=new User({
        username,
        password:hashedPassword,
        isAdmin:false
        });
         await newuser.save()
        .then(user=>{
            return res.send(user)
        })
        .catch(err=>{
            return res.status(401).send('Server error');
        });
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

app.get('/api/committee',async(req,res)=>{
    try{
     const committeMembers=await Committee.find({})
     return res.status(200).send(committeMembers)
        }
        catch(error){
           return res.status(401).send('committee members not found')
        }
})

app.get('/api/events',async(req,res)=>{
    try{
    // const events=await Event.find({})
    const events=await DsrgEvent.find({})
    
     return res.status(200).send(events)
        }
        catch(error){
           return res.status(401).send('Error in fetching events')
        }
})

app.get('/api/blogs',async(req,res)=>{
    try{
     const blogs=await Blog.find({})
     return res.status(200).send(blogs)
        }
        catch(error){
           return res.status(401).send('Error in fetching blogs')
        }
})

app.post('/api/publications/:username',isAuth,async(req,res)=>{
    try {
        const {pname,authors}=req.body;
        const member=await Member.findOne({username:req.params.username})
        if(member){
        const tempPubs=member.reseachers_and_publications;
        tempPubs.push({
            paper_name:pname,
            authors:authors
        })
        member.reseachers_and_publications=tempPubs;

    await member.save()
    .then(m=>{
        return res.status(200).send({member:m,success:true})
    })
    .catch(err=>{
        console.log(err)
        return res.status(500).send({message:'Server error',success:false});
    }); }
    else return res.status(404).send("not found")
    } catch (error) {
     return res.status(401).json({message:error})
    }
 })

 app.put('/api/changePassword',isAuth,async(req,res)=>{
   User.findById(req.user._id, async (err, user) => {
        if (err || !user) {
            return res.status(401).send('user not found');
        }
    
        // Check if the current password is correct
        if (! await bcrypt.compare(req.body.currentPassword, user.password)) {
            return res.status(401).send('Incorrect Current Password');
        }
    
        // Hash the new password
        const hash = await bcrypt.hash(req.body.newPassword, 10);
    
        // Update the user document with the new password
        user.password = hash;
       await user.save((err, updatedUser) => {
          if (err) {
            return res.status(400).send('Failed to update password');
          }
          const generatedToken=jwt.sign({id:updatedUser._id},process.env.JWT_SECRET,{
            expiresIn:'10d'
        })
       return res.json({
          _id:updatedUser._id,
          username:updatedUser.username,
          isAdmin:updatedUser.isAdmin,
          token:generatedToken
        })
        });
      });

 })
 app.post('/api/skills/:username',isAuth,async(req,res)=>{
    try {
        const {skills}=req.body;
        const member=await Member.findOne({username:req.params.username})
        if(member){
        const tempSkills=member.skills;
        let newArray = [];
        let elements = skills.split(",");

          for (let i = 0; i < elements.length; i++) {
         newArray.push(elements[i]);
         }


let mergedArray = [];

for (let i = 0; i < tempSkills.length; i++) {
  if (!mergedArray.includes(tempSkills[i])) {
    mergedArray.push(tempSkills[i]);
  }
}

for (let i = 0; i < newArray.length; i++) {
  if (!mergedArray.includes(newArray[i])) {
    mergedArray.push(newArray[i]);
  }
}




        member.skills=mergedArray;

    await member.save()
    .then(m=>{
        return res.status(200).send({member:m,success:true})
    })
    .catch(err=>{
        console.log(err)
        return res.status(500).send({message:'Server error',success:false});
    }); }
    else return res.status(404).send("not found")
    } catch (error) {
     return res.status(401).json({message:error})
    }
 })

app.get('/api/events/:id',async(req,res)=>{
    try{
    // const event=await Event.findById(req.params.id)
     
     const event=await DsrgEvent.findById(req.params.id)
     return res.status(200).send(event)
        }
        catch(error){
           return res.status(401).send('Error in fetching event')
        }
})

app.get('/api/blogs/:id',async(req,res)=>{
    try{
     const blog=await Blog.findById(req.params.id)
     return res.status(200).send(blog)
        }
        catch(error){
           return res.status(401).send('Error in fetching blog')
        }
})

app.get('/api/members/:username',async(req,res)=>{
  
   try {
    const member=await Member.findOne({username:req.params.username})
   if(member)
   return res.status(200).send(member)
   else return res.status(404).send("not found")
   } catch (error) {
     return res.status(401).json({message:error})
   }
})

app.get('/api/editMember/:id',isAuth,async(req,res)=>{
    
     await Member.findOne({_id:req.params.id})
     .then(member=>res.status(200).send({member,success:true}))
     .catch(err=>res.status(404).send({message:"member not found",success:false}))
 })

 app.post('/api/events',isAuth,isAdmin,upload.array('event_image'),async(req,res)=>{

  /*
    console.log("start")
  const currentDate = new Date();
const year = currentDate.getFullYear();
const month = ('0' + (currentDate.getMonth() + 1)).slice(-2);
const day = ('0' + currentDate.getDate()).slice(-2);
const hours = ('0' + currentDate.getHours()).slice(-2);
const minutes = ('0' + currentDate.getMinutes()).slice(-2);
const dateString = `${year}-${month}-${day}T${hours}:${minutes}`; */

   //let imagePath='';
  /* const imagePath=[]
            if (req.files){
                req.files.map((file)=>{
                   const upload_image=async()=>
                   {
                    console.log("from fun")
                    console.log(file)
                    const extName = path.extname(file.originalname).toString();
                    const file64 = parser.format(extName,file.buffer);
                   // console.log("test from up")
                   // console.log(extName)
                   // console.log(file64)
                   try {
                    const result = await cloudinary.uploader.upload(file64.content,{
                        uploads: "products",
                        // width: 300,
                        // crop: "scale"
                        public_id: `${Date.now()}`,
                        resource_type: "auto",
                    })
                    //console.log("test from cloud")
                    console.log("secure url")
                    console.log(result.secure_url)
                    imagePath.push(result.secure_url)
                   } catch (error) {
                    console.log("up error")
                    console.log(error)
                   }
                   
                   //imagePath=result.secure_url;
                  // 
                   }
                   upload_image()
                })
               
            }
    console.log("imagePath")
   console.log(imagePath)
   const {title,description}=req.body
  // const newEvent=new Event({
    const newEvent=new DsrgEvent({
    image:imagePath,
    title,
    description,
    date:dateString
    });
     await newEvent.save()
    .then(event=>{
        return res.status(200).send({event,success:true})
    })
    .catch(err=>{
        console.log(err)
        return res.status(500).send({message:'Server error',success:false});
    }); 
    console.log("ok")
    console.log(req.file)
    console.log(req.files)*/

    try {
        const results = await Promise.all(
          req.files.map(async file => {
            const extName = path.extname(file.originalname).toString();
            const file64 = parser.format(extName,file.buffer);
            const result = await cloudinary.uploader.upload(file64.content,{
                uploads: "products",
                public_id: `${Date.now()}`,
                resource_type: "image",
                timeOut:120000
            })
            return result;
          })
        );
       // res.send(results);
     
       const imagePath=[]
       results.map((rs)=>imagePath.push(rs.secure_url))

    
       const {title,description}=req.body
      // const newEvent=new Event({
        const newEvent=new DsrgEvent({
        image:imagePath,
        title,
        description,
        date:new Date().toISOString()
        });
         await newEvent.save()
        .then(event=>{
            return res.status(200).send({event,success:true})
        })
        .catch(err=>{
            console.log(err)
            return res.status(500).send({message:'Server error',success:false});
        }); 

      } catch (error) {
       
        console.log(error)
        res.status(500).send(error);
      }

  
 })

 app.post('/api/blogs',isAuth,upload.single('blog_image'),async(req,res)=>{

   
    /*const currentDate = new Date();
 const year = currentDate.getFullYear();
 const month = ('0' + (currentDate.getMonth() + 1)).slice(-2);
 const day = ('0' + currentDate.getDate()).slice(-2);
 const hours = ('0' + currentDate.getHours()).slice(-2);
 const minutes = ('0' + currentDate.getMinutes()).slice(-2);
 const dateString = `${year}-${month}-${day}T${hours}:${minutes}`;
 */
    let imagePath='';
             if (req.file){
                 const extName = path.extname(req.file.originalname).toString();
                 const file64 = parser.format(extName, req.file.buffer);
                 const result = await cloudinary.uploader.upload(file64.content,{
                     uploads: "products",
                     // width: 300,
                     // crop: "scale"
                     public_id: `${Date.now()}`,
                     resource_type: "auto",
                 })
                imagePath=result.secure_url;
             }
 
    const {username,title,description,name}=req.body
    const newBlog=new Blog({
     username,
     name,
     image:imagePath,
     title,
     description,
     date:new Date().toISOString()
     });
      await newBlog.save()
     .then(blog=>{
         return res.status(200).send({blog,success:true})
     })
     .catch(err=>{
         console.log(err)
         return res.status(500).send({message:'Server error',success:false});
     }); 
  })

 app.put('/api/editMember/:id',isAuth,isAdmin,upload.single('image'),async(req,res)=>{
   

    try{
        const member=await Member.findById(req.params.id)
        if(member)
        {
            const {name,email,phone,field_of_interest,description}=req.body;
            
            let imagePath='';
            if (req.file){
                const extName = path.extname(req.file.originalname).toString();
                const file64 = parser.format(extName, req.file.buffer);
                const result = await cloudinary.uploader.upload(file64.content,{
                    uploads: "products",
                    // width: 300,
                    // crop: "scale"
                    public_id: `${Date.now()}`,
                    resource_type: "auto",
                })
                
               // imagePath = String('/' + req.file.destination.split('/').slice(1) + '/' + req.file.filename);
               imagePath=result.secure_url;
            }
    
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


app.post('/api/members',isAuth,isAdmin,async(req,res)=>
{

   const {username,name,email,phone,field_of_interest,jobs,description}=req.body;
  
    if(!(name==="") && !(email==="") && !(phone==="")){
        const isMemberExist=await Member.findOne({email});
    if(isMemberExist)
    {
       return res.status(401).send({message:'This user is already registered',success:false});
    }
    else{
    //const hashedPassword=await bcrypt.hash(password,10);
    const newMember=new Member({
    username,
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
        console.log(err)
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

   try{
    const member=await Member.findById(req.params.id)
    if(member)
    {
        const {company,startDate,endDate,designation,jobDescription}=req.body;
        const tempJobs=member.jobs;
        tempJobs.push({...req.body});
        member.jobs=tempJobs;
        const updatedMember=await member.save();
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


app.get('/api/deleteMember/:id',isAuth,isAdmin,async(req,res)=>{
    try{
        const deletedMember=await Member.findByIdAndRemove(req.params.id)
       return res.status(200).send(deletedMember)
        }
        catch(error){
           return res.status(401).send('User not found')
        }
})




app.get("*", function (req,res) {
  res.sendFile(path.join(__dirname, './client/build/index.html'));
});

app.listen(PORT,(err)=>
{
    if(err) console.log(err)
    else console.log(`Server is running at ${PORT}`)
})