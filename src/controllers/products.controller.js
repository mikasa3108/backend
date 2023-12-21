const productModel = require('../models/products.model')

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