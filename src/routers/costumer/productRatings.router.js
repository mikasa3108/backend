const productratingsRouter = require('express').Router()

const productratingsController = require('../../controllers/customer/productRatings.controller')

productratingsRouter.get('/', productratingsController.getAllProductRatings)

productratingsRouter.get('/:id', productratingsController.getDetailProductRatings)

// productratingsRouter.post('/', productratingsController.createProductRatings)

// productratingsRouter.patch('/:id', productratingsController.updateProductRatings)

// productratingsRouter.delete('/:id', productratingsController.deleteProductRatings)

module.exports = productratingsRouter