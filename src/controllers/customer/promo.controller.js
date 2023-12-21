let promoModel = require('../../models/promo.model')

exports.getAllPromo = async (req, res) => {
    const promo = await promoModel.findAll()
    return res.json({
        success: true,
        message: 'list all promo',
        result: promo
    })
}

exports.getDetailPromo = async (req, res) => {
    const id = parseInt(req.params.id)
    const promo = await promoModel.findOne(id)
    if (!promo[0]) {
        return res.status(404).json({
            success: false,
            message: 'promo not found'
        })
    }
    return res.json({
        success: true,
        message: 'detail promo',
        result: promo[0]
    })
}

// exports.createPromo = async (req, res) => {
//     const data = req.body
//     try {
//         const promo = await promoModel.create(data)
//         return res.json({
//             success: true,
//             message: 'create promo success',
//             result: promo
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

// exports.updatePromo = async (req, res) => {
//     const id = parseInt(req.params.id)
//     const data = req.body
//     try {
//         const promo = await promoModel.update(data, id)
//         return res.json({
//             success: true,
//             message: 'success',
//             result: promo
//         })
//     } catch (err) {
//         return res.status(404).json({
//             success: false,
//             message: 'promo not found'
//         })
//     }
// }

// exports.deletePromo = async (req, res) => {
//     const id = parseInt(req.params.id)
//     try {
//         const promo = await promoModel.delete(id)
//         return res.json({
//             success: true,
//             message: 'success',
//             result: promo
//         })
//     } catch (err) {
//         return res.status(404).json({
//             success: false,
//             message: 'promo not found'
//         })
//     }
// }