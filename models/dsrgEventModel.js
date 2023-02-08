const mongoose=require('mongoose')
const Schema=mongoose.Schema


const dsrgEventSchema=new Schema({
image:[String],
title:{
    type:String,
   
},
description:{
    type:String,
   
},
date:{
    type:String,
   
}
})

const DsrgEvent=mongoose.model('dsrg_event',dsrgEventSchema)
module.exports=DsrgEvent