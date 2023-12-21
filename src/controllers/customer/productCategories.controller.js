let productcategoriesModel = require('../../models/productCategories.model')

exports.getAllProductCategories = async (req, res) => {
    const productCategories = await productcategoriesModel.findAll()
    return res.json({
        success: true,
        message: 'list all productcategories',
        result: productCategories
    })
}

exports.getDetailProductCategories = async (req, res) => {
    const id = parseInt(req.params.id)
    const productCategories = await productcategoriesModel.findOne(id)
    if (!productCategories[0]) {
        return res.status(404).json({
            success: false,
            message: 'productcategories not found'
        })
    }
    return res.json({
        success: true,
        message: 'detail productcategories',
        result: productCategories[0]
    })
}

// exports.createProductCategories = async (req, res) => {
//     const data = req.body
//     try {
//         const productCategories = await productcategoriesModel.create(data)
//         return res.json({
//             success: true,
//             message: 'create productcategories success',
//             result: productCategories
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

// exports.updateProductCategories = async (req, res) => {
//     const id = parseInt(req.params.id)
//     const data = req.body
//     try {
//         const productCategories = await productcategoriesModel.update(data, id)
//         return res.json({
//             success: true,
//             message: 'success',
//             result: productCategories
//         })
//     } catch (err) {
//         return res.status(404).json({
//             success: false,
//             message: 'productcategories not found'
//         })
//     }
// }

// exports.deleteProductCategories = async (req, res) => {
//     const id = parseInt(req.params.id)
//     try {
//         const productCategories = await productcategoriesModel.delete(id)
//         return res.json({
//             success: true,
//             message: 'success',
//             result: productCategories
//         })
//     } catch (err) {
//         return res.status(404).json({
//             success: false,
//             message: 'productcategories not found'
//         })
//     }
// }