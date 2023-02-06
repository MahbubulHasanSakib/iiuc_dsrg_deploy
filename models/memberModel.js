const mongoose=require('mongoose')
const Schema=mongoose.Schema


const jobSchema = new Schema(
    {
        company:{
            type:String
        },
        startDate:{
            type:String
        },
        endDate:{
            type:String
        },
        designation:{
            type:String
        },
        jobDescription:{
            type:String
        }
    }
)

const publicationSchema = new Schema(
    {
        paper_name:{type:String},
        authors:{type:String}
    }
)

const memberSchema=new Schema({
profileImg:{
        type:String
},
name:{
    type:String,
    required:true
},
email:{
    type:String,
    required:true,
    unique:true
},
username:{
    type:String,
    required:true,
    unique:true
},
phone:{
    type:String,
    required:true
},
field_of_interest:{
    type:String,
    
},
description:{
    type:String,
    
},
jobs:[jobSchema],
isAdmin:{
    type:Boolean,
    default:false
},
reseachers_and_publications:[publicationSchema],
skills:[String],
},{timestamps:true})

const Member=mongoose.model('member',memberSchema)
module.exports=Member