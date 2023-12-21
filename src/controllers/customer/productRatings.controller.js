let productratingsModel = require('../../models/productRatings.model')

exports.getAllProductRatings = async (req, res) => {
    const productRatings = await productratingsModel.findAll()
    return res.json({
        success: true,
        message: 'list all productratings',
        result: productRatings
    })
}

exports.getDetailProductRatings = async (req, res) => {
    const id = parseInt(req.params.id)
    const productRatings = await productratingsModel.findOne(id)
    if (!productRatings[0]) {
        return res.status(404).json({
            success: false,
            message: 'productratings not found'
        })
    }
    return res.json({
        success: true,
        message: 'detail productratings',
        result: productRatings[0]
    })
}

// exports.createProductRatings = async (req, res) => {
//     const data = req.body
//     try {
//         const productRatings = await productratingsModel.create(data)
//         return res.json({
//             success: true,
//             message: 'create productratings success',
//             result: productRatings
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

// exports.updateProductRatings = async (req, res) => {
//     const id = parseInt(req.params.id)
//     const data = req.body
//     try {
//         const productRatings = await productratingsModel.update(data, id)
//         return res.json({
//             success: true,
//             message: 'success',
//             result: productRatings
//         })
//     } catch (err) {
//         return res.status(404).json({
//             success: false,
//             message: 'productratings not found'
//         })
//     }
// }

// exports.deleteProductRatings = async (req, res) => {
//     const id = parseInt(req.params.id)
//     try {
//         const productRatings = await productratingsModel.delete(id)
//         return res.json({
//             success: true,
//             message: 'success',
//             result: productRatings
//         })
//     } catch (err) {
//         return res.status(404).json({
//             success: false,
//             message: 'productratings not'
//         })
//     }
// }