const mongoose=require('mongoose')
const Schema=mongoose.Schema


const facultySchema=new Schema({
username:{
        type:String,
       required:true
    },
name:{
    type:String,
   // required:true
},
teaching_designation:{
    type:String,
    //required:true
},
dept:{
    type:String,
    //required:true
},
section:{
    type:String,
    //required:true
},
session:{
    type:String,
    //required:true
},
image:{
    type:String,
    //required:true
}
})

const Faculty=mongoose.model('faculty',facultySchema)
module.exports=Faculty