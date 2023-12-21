const userModel = require('../models/users.model')
const argon = require('argon2')
const jwt = require("jsonwebtoken")



exports.login = async (req, res)=>{
    try{
        const {email, password} = req.body
        const user = await userModel.findOneByEmail(email)

        // cara standar dengan if else
        // if(!user){
        //     throw Error('wrong')
        // }
        // const verify = await argon.verify(user.password)
        // if(verify){
        //     return res.json({
        //         success: true,
        //         message: 'login success',
        //         results: {
        //             token : 'abc123'
        //         }
        //     })
        // } else{
        //     throw Error('wrong')
        // }

        // simpel dan rapi dengan negasi
        if(!user){
            throw Error('wrong')
        }
        const verify = await argon.verify(user.password, password)
        if(!verify){
            throw Error('wrong')
        }

        // penggunaan jwt
        const payload = {
            id: user.id,
            role: user.role
        }
        const token = jwt.sign(payload, process.env.APP_SECRET || 'secretkey')
        return res.json({
            success: true,
            message: 'login success',
            results: {
                token
            }
        })
    }catch(err){
        if(err.message === 'wrong'){
            return res.status(401).json({
                success: false,
                message: 'wrong email or password'
            })
        }
        console.log(err)
        return res.status(500).json({
            success: false,
            message: 'internal server error'
        })
    }

    // const {username, password} = req.body
    // if(username === 'wisnu123' && password === 'wisnu123'){
    //     return res.json({
    //         success: true,
    //         message: 'login success'
    //     })
    // }else{
    //     return res.json({
    //         success: false,
    //         message: 'wrong username or password'
    //     })
    // }
}

exports.register = async (req, res)=>{
    try{
        const {fullName, email, password, phoneNumber, role} = req.body
        
        const hashed = await argon.hash(password)
        
        const user =  userModel.create({
            fullName,
            email,
            password: hashed,
            phoneNumber,
            role
        })
        return res.json({
            success: true,
            message: 'register success'
        })
    }catch(err){
        console.log(err)
        return res.status(500).json({
            success: false,
            message: 'internal server error'
        })
    }
}