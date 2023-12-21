const categoriesRouter = require('express').Router()

const categoriesController = require('../../controllers/admin/categories.controller')

categoriesRouter.get('/', categoriesController.getAllCategories)

categoriesRouter.get('/:id', categoriesController.getDetailCategories)

categoriesRouter.post('/', categoriesController.createCategories)

categoriesRouter.patch('/:id', categoriesController.updateCategories)

categoriesRouter.delete('/:id', categoriesController.deleteCategories)

module.exports = categoriesRouter