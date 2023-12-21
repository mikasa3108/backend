const orderdetailsRouter = require('express').Router()

const orderdetailsController = require('../../controllers/admin/orderDetails.controller')

orderdetailsRouter.get('/', orderdetailsController.getAllOrderDetails)

orderdetailsRouter.get('/:id', orderdetailsController.getDetailOrderDetails)

orderdetailsRouter.post('/', orderdetailsController.createOrderDetails)

orderdetailsRouter.patch('/:id', orderdetailsController.updateOrderDetails)

orderdetailsRouter.delete('/:id', orderdetailsController.deleteOrderDetails)

module.exports = orderdetailsRouter