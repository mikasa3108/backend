let orderModel = require('../../models/orders.model')

exports.getAllOrder = async (req, res) => {
    const order = await orderModel.findAll()
    return res.json({
        success: true,
        message: 'list all order',
        result: order
    })
}

exports.getDetailOrder = async (req, res) => {
    const id = parseInt(req.params.id)
    const order = await orderModel.findOne(id)
    if (!order[0]) {
        return res.status(404).json({
            success: false,
            message: 'order not found'
        })
    }
    return res.json({
        success: true,
        message: 'search order success',
        result: order[0]
    })
}

exports.createOrder = async (req, res) => {
    const data = req.body
    try {
        const order = await orderModel.create(data)
        return res.json({
            success: true,
            message: 'create order success',
            result: order
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

exports.updateOrder = async (req, res) => {
    const id = parseInt(req.params.id)
    const data = req.body
    try {
        const order = await orderModel.update(data, id)
        return res.json({
            success: true,
            message: 'success',
            result: order
        })
    } catch (err) {
        return res.status(404).json({
            success: false,
            message: 'order not found'
        })
    }
}

exports.deleteOrder = async (req, res) => {
    const id = parseInt(req.params.id)
    try {
        const order = await orderModel.delete(id)
        return res.json({
            success: true,
            message: 'success',
            result: order
        })
    } catch (err) {
        return res.status(404).json({
            success: false,
            message: 'order not found'
        })
    }
}