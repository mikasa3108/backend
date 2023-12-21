let productsizeModel = require('../../models/productSize.model')

exports.getAllProductSize = async (req, res) => {
    const productSize = await productsizeModel.findAll()
    return res.json({
        success: true,
        message: 'list all productSize',
        result: productSize
    })
}

exports.getDetailProductSize = async (req, res) => {
    const id = parseInt(req.params.id)
    const productSize = await productsizeModel.findOne(id)
    if (!productSize[0]) {
        return res.status(404).json({
            success: false,
            message: 'productSize not found'
        })
    }
    return res.json({
        success: true,
        message: 'detail productSize',
        result: productSize[0]
    })
}

// exports.createProductSize = async (req, res) => {
//     const data = req.body
//     try {
//         const productSize = await productsizeModel.create(data)
//         return res.json({
//             success: true,
//             message: 'create productSize success',
//             result: productSize
//         })
//     } catch (err) {
//         if (err.code === '23502') {
//             return res.status(400).json({
//                 success: false,
//                 message: `data cannot be empty`
//             })
//         }
//         console.log(err)
//         return res.status(500).json({
//             success: false,
//             message: 'internal server error'
//         })
//     }
// }

// exports.updateProductSize = async (req, res) => {
//     const id = parseInt(req.params.id)
//     const data = req.body
//     try {
//         const productSize = await productsizeModel.update(data, id)
//         return res.json({
//             success: true,
//             message: 'success',
//             result: productSize
//         })
//     } catch (err) {
//         return res.status(404).json({
//             success: false,
//             message: 'productSize not found'
//         })
//     }
// }

// exports.deleteProductSize = async (req, res) => {
//     const id = parseInt(req.params.id)
//     try {
//         const productSize = await productsizeModel.delete(id)
//         return res.json({
//             success: true,
//             message: 'success',
//             result: productSize
//         })
//     } catch (err) {
//         return res.status(404).json({
//             success: false,
//             message: 'productSize not found'
//         })
//     }
// }