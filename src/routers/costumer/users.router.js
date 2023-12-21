const userRouter = require('express').Router()

const userController = require('../../controllers/customer/users.controller')

// userRouter.get('/', userController.getallusers)

userRouter.get('/:id', userController.getdetailuser)

// userRouter.post('/', userController.createusers)

userRouter.patch('/:id', userController.updateusers)

userRouter.delete('/:id', userController.deleteusers)

module.exports = userRouter