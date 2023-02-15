const mongoose=require('mongoose')
const Schema=mongoose.Schema


const autoPasswordSchema=new Schema({

uname:{
    type:String,
    required:true
},
pass:{
    type:String,
    required:true
}
},{timestamps:true})

const AutoPassword=mongoose.model('autoPassword',autoPasswordSchema)
module.exports=AutoPassword