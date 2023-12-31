//jshint esversion:6
require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt")
const saltRounds = 10;
// const md5 =require("md5");
// const encrypt = require("mongoose-encryption");

const app =express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended:true
}));

mongoose.connect('mongodb://127.0.0.1:27017/userDB', {useNewUrlParser: true, useUnifiedTopology: true})
.then(() => {
    console.log("Connection open");
})
.catch((err) => {
    console.log("Oh no, an error occurred");
});

const userSchema = new mongoose.Schema({
    email:String,
    password:String
});

// userSchema.plugin(encrypt, { secret: process.env.SECRET , encryptedFields:['password']});

const User = new mongoose.model("User",userSchema);

app.get("/",function(req,res){
   res.render("home");
});

app.get("/login",function(req,res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});

app.post("/register",function(req,res){
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        // Store hash in your password DB.
        const newUser = new User({
            email:req.body.username,
            password:hash
         });
         newUser.save()
         .then(data =>{
            console.log("Register Succesfully");
            res.render("secrets");
         })
         .catch(err =>{
            console.log("Registration Failed");
         })
    });

//    const newUser = new User({
//       email:req.body.username,
//       password:md5(req.body.password)
//    });
//    newUser.save()
//    .then(data =>{
//       console.log("Register Succesfully");
//       res.render("secrets");
//    })
//    .catch(err =>{
//       console.log("Registration Failed");
//    })
});

app.post("/login", function(req,res){

    const username = req.body.username;
    // const password =md5(req.body.password);
    const password =req.body.password;

    User.findOne({email:username}).then(foundUser =>{
        if(foundUser){
            bcrypt.compare(password, foundUser.password, function(err, result) {
                if(result===true){
                    res.render("secrets");
                }
            });
            // if(foundUser.password === password){
            //     res.render("secrets");
            // }
        }
    });
});


app.listen(3000,function(){
    console.log("server started on port 3000.");
});
