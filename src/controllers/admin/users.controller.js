let userModel = require('../../models/users.model')
const argon = require('argon2')

exports.getallusers = async (req, res) => {
    const users = await userModel.findAll()
    return res.json({
        success: true,
        message: 'list all users',
        result: users
    })
}

exports.getdetailuser = async (req, res) => {
    const id = parseInt(req.params.id)
    const user = await userModel.findOne(id)
    if (!user[0]) {
        return res.status(404).json({
            success: false,
            message: 'user not found'
        })
    }
    return res.json({
        success: true,
        message: 'detail user',
        result: user[0]
    })
}

exports.createusers = async (req, res) => {
    try {
        // const {fullName, email, password, address, picture, phoneNumber, role} = req.body
        // const hashed = await argon.hash(password)
        // const user = await userModel.create({
        //     fullName,
        //     email,
        //     password: hashed,
        //     address,
        //     picture,
        //     phoneNumber,
        //     role
        // })

        if(req.body.password){
            req.body.password = await argon.hash(req.body.password)
        }
        const user = await userModel.create(req.body)
        return res.json({
            success: true,
            message: 'create success',
            result: user
        })
    } catch (err) {
        if (err.code === '23502') {
            return res.status(400).json({
                success: false,
                message: `data cannot be empty`
            })
        }
        console.log(err)
        return res.status(500).json({
            success: false,
            message: 'internal server error'
        })
    }
}

exports.updateusers = async (req, res) => {
    try {
        // const {id} = req.params
        // const {password} = req.body
        // const hashed = await argon.hash(password)
        // const user = await userModel.update({password: hashed}, id)

        const{id} = req.params
        const data = {
            ...req.body
        }
        if(req.body.password){
            data.password = await argon.hash(req.body.password)
        }
        const user = await userModel.update(data, id) 
        return res.json({
            success: true,
            message: 'update success',
            results: user
        })
    } catch (err) {
        if(err.code === "42703"){
            return res.status(404).json({
                success: false,
                message: 'user not found'
            })   
        }
    console.log(err)
    return res.status(500).json({
            success: false,
            message: 'internet server error'
        })
    } 
}

exports.deleteusers = async (req, res) => {
    const id = parseInt(req.params.id)
    try {
        const user = await userModel.delete(id)
        return res.json({
            success: true,
            message: 'delete success',
            result: user
        })
    } catch (err) {
        return res.status(404).json({
            success: false,
            message: 'user not found'
        })
    }
}