const messageRouter = require('express').Router()

const messageController = require('../../controllers/customer/message.controller')

messageRouter.get('/', messageController.getAllMessage)

messageRouter.get('/:id', messageController.getDetailMessage)

messageRouter.post('/', messageController.createMessage)

messageRouter.patch('/:id', messageController.updateMessage)

messageRouter.delete('/:id', messageController.deleteMessage)

module.exports = messageRouter