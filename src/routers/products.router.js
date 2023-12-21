const productRouter = require('express').Router()

const productController = require('../controllers/products.controller')

productRouter.get('/', productController.getallproducts)

productRouter.get('/:id', productController.getdetailproduct)

module.exports = productRouter