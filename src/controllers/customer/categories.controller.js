let categoriesModel = require('../../models/categories.model')

exports.getAllCategories = async (req, res) => {
    const categories = await categoriesModel.findAll()
    return res.json({
        success: true,
        message: 'list all categories',
        result: categories
    })
}

exports.getDetailCategories = async (req, res) => {
    const id = parseInt(req.params.id)
    const categories = await categoriesModel.findOne(id)
    if (!categories[0]) {
        return res.status(404).json({
            success: false,
            message: 'categories not found'
        })
    }
    return res.json({
        success: true,
        message: 'detail categories',
        result: categories[0]
    })
}

// exports.createCategories = async (req, res) => {
//     const data = req.body
//     try {
//         const categories = await categoriesModel.create(data)
//         return res.json({
//             success: true,
//             message: 'create categories success',
//             result: categories
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

// exports.updateCategories = async (req, res) => {
//     const id = parseInt(req.params.id)
//     const data = req.body
//     try {
//         const categories = await categoriesModel.update(data, id)
//         return res.json({
//             success: true,
//             message: 'success',
//             result: categories
//         })
//     } catch (err) {
//         return res.status(404).json({
//             success: false,
//             message: 'categories not found'
//         })
//     }
// }

// exports.deleteCategories = async (req, res) => {
//     const id = parseInt(req.params.id)
//     try {
//         const categories = await categoriesModel.delete(id)
//         return res.json({
//             success: true,
//             message: 'success',
//             result: categories
//         })
//     } catch (err) {
//         return res.status(404).json({
//             success: false,
//             message: 'categories not found'
//         })
//     }
// }