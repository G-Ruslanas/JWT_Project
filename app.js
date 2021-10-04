const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const mongoose = require('mongoose');
const User = require('./model/user');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'asdasdasdasfafasafa7785asd31$5%asdadasdasdasd';

mongoose.connect('mongodb://localhost:27017/login-app-db');


const app = express();
// app.use(express.static("public"));
app.use("/", express.static(path.join(__dirname, 'static')));
// app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());

app.post("/api/change-password", async function(req,res){

    const {token, newpassword: plainTextPassword } = req.body

    try {
		const user = jwt.verify(token, JWT_SECRET)

		const _id = user.id

		const password = await bcrypt.hash(plainTextPassword, 10)

		await User.updateOne(
			{ _id },
			{
				$set: { password }
			}
		)
		res.json({ status: 'ok' })
	} catch (error) {
		console.log(error)
		res.json({ status: 'error', error: 'Something went wrong' })
	}


});



app.post('/api/login', async function(req, res) {

    const {username, password } = req.body;


    const user = await User.findOne({username: req.body.username});
    if(!user){
        return res.json({status: 'error', error: 'Invalid username/password'})
    }

    if(await bcrypt.compare(password, user.password)){
        const token = jwt.sign({
            id: user._id,
            username: user.username
        }, JWT_SECRET)
        return res.json({status: 'ok', data: token})
    }

    res.json({status: 'error', error: 'Invalid username/password'})
})


app.post("/api/register", async function(req, res){
  
    const {username, password: plainTextPassword} = req.body;

    if(!username || typeof username !== 'string'){
        return res.json({status: 'error', error: 'Invalid username'})
    }
    if(!plainTextPassword || typeof plainTextPassword !== 'string'){
        return res.json({status: 'error', error: 'Invalid password'})
    }
    if(plainTextPassword.length <5){
        return res.json({status: 'error', error: 'Password to small. Should be atleast 6 characters'})
    }

    const password = await bcrypt.hash(plainTextPassword, 10);

    try {
        const response = await User.create({
            username,
            password
        })
        console.log('User created sucessfully: ', response);
    } catch(error){
        if(error.code === 11000){
            //duplicate key
            return res.json({status: 'error', error: "Username already in use"});
        } 
        throw error
    }
    res.json({status:'ok'});
});


app.listen(3000, function(){
    console.log("Server up at 3000");
});