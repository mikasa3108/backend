const roleCheckMiddleware = (role)=>{
    return(req, res, next)=>{
        if(req.user.role !== role){
            return res.status(400).json({
                success: false,
                message: 'forbidden access'
            })
        }
        next()
    }
}
module.exports = roleCheckMiddleware