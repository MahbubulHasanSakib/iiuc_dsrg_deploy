const mongoose=require('mongoose')
const Schema=mongoose.Schema


const committeeSchema=new Schema({
name:{
    type:String,
   // required:true
},
username:{
    type:String,
    //required:true
},
designation:{
    type:String,
    //required:true
},
section:{
    type:String,
    //required:true
},
section_order:{
    type:Number
    //required:true
},
session:{
    type:String,
    //required:true
}
})

const Committee=mongoose.model('committee',committeeSchema)
module.exports=Committee