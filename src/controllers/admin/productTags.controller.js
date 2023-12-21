let producttagsModel = require('../../models/productTags.model')

exports.getAllProductTags = async (req, res) => {
    const productTags = await producttagsModel.findAll()
    return res.json({
        success: true,
        message: 'list all producttags',
        result: productTags
    })
}

exports.getDetailProductTags = async (req, res) => {
    const id = parseInt(req.params.id)
    const productTags = await producttagsModel.findOne(id)
    if (!producttags[0]) {
        return res.status(404).json({
            success: false,
            message: 'producttags not found'
        })
    }
    return res.json({
        success: true,
        message: 'detail producttags',
        result: productTags[0]
    })
}

exports.createProductTags = async (req, res) => {
    const data = req.body
    try {
        const productTags = await producttagsModel.create(data)
        return res.json({
            success: true,
            message: 'create producttags success',
            result: productTags
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

exports.updateProductTags = async (req, res) => {
    const id = parseInt(req.params.id)
    const data = req.body
    try {
        const productTags = await producttagsModel.update(data, id)
        return res.json({
            success: true,
            message: 'success',
            result: productTags
        })
    } catch (err) {
        return res.status(404).json({
            success: false,
            message: 'producttags not found'
        })
    }
}

exports.deleteProductTags = async (req, res) => {
    const id = parseInt(req.params.id)
    try {
        const productTags = await producttagsModel.delete(id)
        return res.json({
            success: true,
            message: 'success',
            result: productTags
        })
    } catch (err) {
        return res.status(404).json({
            success: false,
            message: 'producttags not found (update or delete on table "producttags" violates foreign key constraint "orderDetails_producttagsId_fkey" on table "orderDetails")'
        })
    }
}