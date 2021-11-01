const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username:{
        type: String,
        required:true,
        min:5,
        max:10,
        unique:true,
    },
    email:{
        type:String,
        required:true,
        unique:true,
    },
    password:{
        type:String,
        required:true,
    },
    verified:{
        type:Boolean,
        default:false,
    },
    resetLink:{
        type:String,
        default:''
    }
},{timestamps: true});

module.exports = mongoose.model('User', UserSchema);