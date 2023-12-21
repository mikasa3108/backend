const producttagsRouter = require('express').Router()

const producttagsController = require('../../controllers/customer/productTags.controller')

producttagsRouter.get('/', producttagsController.getAllProductTags)

producttagsRouter.get('/:id', producttagsController.getDetailProductTags)

// producttagsRouter.post('/', producttagsController.createProductTags)

// producttagsRouter.patch('/:id', producttagsController.updateProductTags)

// producttagsRouter.delete('/:id', producttagsController.deleteProductTags)

module.exports = producttagsRouter