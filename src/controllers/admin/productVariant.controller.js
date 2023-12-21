let productvariantModel = require('../../models/productVariant.model')

exports.getAllProductVariant = async (req, res) => {
    const productVariant = await productvariantModel.findAll()
    return res.json({
        success: true,
        message: 'list all productvariant',
        result: productVariant
    })
}

exports.getDetailProductVariant = async (req, res) => {
    const id = parseInt(req.params.id)
    const productVariant = await productvariantModel.findOne(id)
    if (!productVariant[0]) {
        return res.status(404).json({
            success: false,
            message: 'productVariant not found'
        })
    }
    return res.json({
        success: true,
        message: 'detail productVariant',
        result: productVariant[0]
    })
}

exports.createProductVariant = async (req, res) => {
    const data = req.body
    try {
        const productVariant = await productvariantModel.create(data)
        return res.json({
            success: true,
            message: 'create productVariant success',
            result: productVariant
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

exports.updateProductVariant = async (req, res) => {
    const id = parseInt(req.params.id)
    const data = req.body
    try {
        const productVariant = await productvariantModel.update(data, id)
        return res.json({
            success: true,
            message: 'success',
            result: productVariant
        })
    } catch (err) {
        return res.status(404).json({
            success: false,
            message: 'productVariant not found'
        })
    }
}

exports.deleteProductVariant = async (req, res) => {
    const id = parseInt(req.params.id)
    try {
        const productVariant = await productvariantModel.delete(id)
        return res.json({
            success: true,
            message: 'success',
            result: productVariant
        })
    } catch (err) {
        return res.status(404).json({
            success: false,
            message: 'productVariant not found'
        })
    }
}