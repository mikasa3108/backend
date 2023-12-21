const productvariantRouter = require('express').Router()

const productvariantController = require('../../controllers/customer/productVariant.controller')

productvariantRouter.get('/', productvariantController.getAllProductVariant)

productvariantRouter.get('/:id', productvariantController.getDetailProductVariant)

// productvariantRouter.post('/', productvariantController.createProductVariant)

// productvariantRouter.patch('/:id', productvariantController.updateProductVariant)

// productvariantRouter.delete('/:id', productvariantController.deleteProductVariant)

module.exports = productvariantRouter