const mongoose=require('mongoose')
const Schema=mongoose.Schema


const eventSchema=new Schema({
image:{
    type:String,
},
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

const Event=mongoose.model('event',eventSchema)
module.exports=Event