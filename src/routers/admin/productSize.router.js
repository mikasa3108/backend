const productsizeRouter = require('express').Router()

const productsizeController = require('../../controllers/admin/productSize.controller')

productsizeRouter.get('/', productsizeController.getAllProductSize)

productsizeRouter.get('/:id', productsizeController.getDetailProductSize)

productsizeRouter.post('/', productsizeController.createProductSize)

productsizeRouter.patch('/:id', productsizeController.updateProductSize)

productsizeRouter.delete('/:id', productsizeController.deleteProductSize)

module.exports = productsizeRouter