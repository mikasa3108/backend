let messageModel = require('../../models/message.model')

exports.getAllMessage = async (req, res) => {
    const message = await messageModel.findAll()
    return res.json({
        success: true,
        message: 'list all message',
        result: message
    })
}

exports.getDetailMessage = async (req, res) => {
    const id = parseInt(req.params.id)
    const message = await messageModel.findOne(id)
    if (!message[0]) {
        return res.status(404).json({
            success: false,
            message: 'message not found'
        })
    }
    return res.json({
        success: true,
        message: 'detail message',
        result: message[0]
    })
}

exports.createMessage = async (req, res) => {
    const data = req.body
    try {
        const message = await messageModel.create(data)
        return res.json({
            success: true,
            message: 'create message success',
            result: message
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

exports.updateMessage = async (req, res) => {
    const id = parseInt(req.params.id)
    const data = req.body
    try {
        const message = await messageModel.update(data, id)
        return res.json({
            success: true,
            message: 'success',
            result: message
        })
    } catch (err) {
        return res.status(404).json({
            success: false,
            message: 'message not found'
        })
    }
}

exports.deleteMessage = async (req, res) => {
    const id = parseInt(req.params.id)
    try {
        const message = await messageModel.delete(id)
        return res.json({
            success: true,
            message: 'success',
            result: message
        })
    } catch (err) {
        return res.status(404).json({
            success: false,
            message: 'message not found'
        })
    }
}