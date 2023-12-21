const productModel = require('../../models/products.model')
const fs = require('fs/promises')
const path = require('path')
const uploadMiddleware = require('../../middlewares/upload.middleware')
const upload = uploadMiddleware('products').single('image')

exports.getallproducts = async (req, res) => {
    try {
        const {search, sortBy, orderBy, page=1, limit } = req.query
        const limitData = parseInt(limit) || 10
        const count = await productModel.countAll(search)
        const products = await productModel.findAll(search, sortBy, orderBy, page, limit)
        // if(!products.length < 1){
        //     throw new Error('no_data')
        // }

        const totalPage = Math.ceil(count / limitData)
        const nextPage = parseInt(page) + 1
        const prevPage = parseInt(page) - 1
        // const products = await productModel.findAll()
        return res.json({
            success: true,
            message: 'list all product',
            pageInfo: {
                currentPage: parseInt(page),
                totalPage,
                nextPage: nextPage <= totalPage ? nextPage : null,
                prevPage: prevPage >= 1 ? prevPage : null,
                totalData: count
            },
            results: products
        })
    } catch (err) {
        if (err.message === 'no_data') {
            return res.status(404).json({
                success: false,
                message: 'no data'
            })
        }
        console.log(err)
        return res.status(500).json({
            success: false,
            message: 'internal server error'
        })
    }
}

exports.getdetailproduct = async (req, res) => {
    // //SINGKAT
    // return res.json({
    //     success: true,
    //     message:'detail product'
    // })

    const id = parseInt(req.params.id)
    const product = await productModel.findOne(id)
    if (!product[0]) {
        return res.status(404).json({
            success: false,
            message: 'product not found'
        })
    }
    return res.json({
        success: true,
        message: 'detail product',
        results: product[0]
    })
}

// exports.createproduct = async (req, res) => {

//     upload(req, res, async (err) => {
//         try {
//             if (err) {
//                 throw err
//             }
//             if (req.file) {
//                 req.body.image = req.file.filename
//             }
//             const product = await productModel.create(req.body)

//             // // PROGRAM PENAMAAN DENGAN id NAMUN MASUH BUG
//             // if(req.file){
//             //     const exstensi = {
//             //         'image/jpeg' : '.jpg',
//             //         'image/png' : '.png'
//             //     }
//             //     // req.body.image = req.file.filename
//             //     const uploadLocation = path.join(global.path, 'uploads', 'products')
//             //     const fileLocation = path.join(uploadLocation, req.file.filename)
//             //     const filename = `${product.id}${exstensi[req.file.mimetype]}`
//             //     const newLocation = path.join(uploadLocation, filename)

//             //     await fs.rename(fileLocation, newLocation)
//             //     const renamedProduct = await productModel.update(product.id, {
//             //         image: filename,
//             //     })
//             //         return res.json({
//             //     success: true,
//             //     message: 'success',
//             //     results: renamedProduct
//             //         })
//             // }
//             // const product = await productModel.create(req.body)
//             return res.json({
//                 success: true,
//                 message: 'create success',
//                 results: product
//             })
//         } catch (err) {
//             //ERROR UNTUK limits
//             if (err.message === 'File too large') {
//                 return res.status(400).json({
//                     success: false,
//                     message: err.message
//                 })
//             }
//             //ERROR UNTUK file Filter
//             if (err.message === 'file_issue') {
//                 return res.status(400).json({
//                     success: false,
//                     message: 'File not support'
//                 })
//             }
//             console.log(err)
//             return res.status(500).json({
//                 success: false,
//                 message: 'internal server error'
//             })
//         }
//     })
// }

// exports.updateproduct = async (req, res) => {
//     upload(req, res, async (err) => {
//         try {
//             if (err) {
//                 throw err
//             }
//             const id = (req.params.id)
//             const data = await productModel.findOne(id)

//             if (!data) {
//                 throw new Error('not found')
//             }

//             if (req.file) {
//                 if (data.image) {
//                     const uploadLocation = path.join(global.path, 'uploads', 'products', data.image)
//                     fs.rm(uploadLocation)
//                 }
//                 req.body.image = req.file.filename
//             }
//             const product = await productModel.update(id, req.body)
//             return res.json({
//                 success: true,
//                 message: 'update success',
//                 results: product
//             })
//         } catch (err) {
//             if (err.message === "not found") {
//                 return res.status(404).json({
//                     success: false,
//                     message: 'product not found'
//                 })
//             }
//             if (err.message === 'file_issue') {
//                 return res.status(400).json({
//                     success: false,
//                     message: 'File not support'
//                 })
//             }
//             console.log(err)
//             return res.status(500).json({
//                 success: false,
//                 message: 'internet server error'
//             })
//         }
//     })
// }

// exports.deleteproduct = async (req, res) => {
//     try {
//         const id = (req.params.id)
//         const deleted = await productModel.delete(id)
//         if (deleted.image) {
//             const uploadLocation = path.join(global.path, 'uploads', 'products', deleted.image)
//             fs.rm(uploadLocation)
//         }
//         return res.json({
//             success: true,
//             message: 'delete success',
//             results: deleted
//         })
//     } catch (err) {
//         return res.status(404).json({
//             success: false,
//             message: 'product not found'
//         })
//     }
// }