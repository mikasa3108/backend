const jwt = require('jsonwebtoken')

const authMiddleware = (req, res, next)=>{
    try{
        const rawToken = req.headers.authorization || ''
        // karena bentuknya Bearer jadi harus di logickan
        const profix = "Bearer "

        if(!rawToken.startsWith(profix)){
            throw Error('invalid')
        }
        const token = rawToken.slice(profix.length)
        req.user = jwt.verify(token, process.env.APP_SECRET || 'secretkey')
        next()
    }catch(err){
        if(err.message === 'invalid'){
            return res.status(401).json({
                success: false,
                message: 'invalid token'
            })
        }
        console.log(err)
        return res.status(500).json({
            success: false,
            message: 'internal server error'
        })
    }
}
module.exports = authMiddleware