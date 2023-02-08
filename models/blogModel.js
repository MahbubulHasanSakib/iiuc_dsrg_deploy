const mongoose=require('mongoose')
const Schema=mongoose.Schema


const blogSchema=new Schema({
username:{
        type:String
},
name:{
    type:String
},
image:{
    type:String,
},
title:{
    type:String,
    required:true
},
description:{
    type:String,
    required:true
},
date:{
    type:String,
   
}
})

const Blog=mongoose.model('blog',blogSchema)
module.exports=Blog