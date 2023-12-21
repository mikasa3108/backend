let orderdetailsModel = require('../../models/orderDetails.model')

exports.getAllOrderDetails = async (req, res) => {
    const orderDetails = await orderdetailsModel.findAll()
    return res.json({
        success: true,
        message: 'list all orderdetails',
        result: orderDetails
    })
}

exports.getDetailOrderDetails = async (req, res) => {
    const id = parseInt(req.params.id)
    const orderDetails = await orderdetailsModel.findOne(id)
    if (!orderDetails[0]) {
        return res.status(404).json({
            success: false,
            message: 'orderdetails not found'
        })
    }
    return res.json({
        success: true,
        message: 'detail orderdetails',
        result: orderDetails[0]
    })
}

exports.createOrderDetails = async (req, res) => {
    const data = req.body
    try {
        const orderDetails = await orderdetailsModel.create(data)
        return res.json({
            success: true,
            message: 'create orderdetails success',
            result: orderDetails
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

exports.updateOrderDetails = async (req, res) => {
    const id = parseInt(req.params.id)
    const data = req.body
    try {
        const orderDetails = await orderdetailsModel.update(data, id)
        return res.json({
            success: true,
            message: 'success',
            result: orderDetails
        })
    } catch (err) {
        return res.status(404).json({
            success: false,
            message: 'orderdetails not found'
        })
    }
}

exports.deleteOrderDetails = async (req, res) => {
    const id = parseInt(req.params.id)
    try {
        const orderDetails = await orderdetailsModel.delete(id)
        return res.json({
            success: true,
            message: 'success',
            result: orderDetails
        })
    } catch (err) {
        return res.status(404).json({
            success: false,
            message: 'orderdetails not found'
        })
    }
}