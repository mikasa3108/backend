const tagsRouter = require('express').Router()

const tagsController = require('../../controllers/admin/tags.controller')

tagsRouter.get('/', tagsController.getAllTags)

tagsRouter.get('/:id', tagsController.getDetailTags)

tagsRouter.post('/', tagsController.createTags)

tagsRouter.patch('/:id', tagsController.updateTags)

tagsRouter.delete('/:id', tagsController.deleteTags)

module.exports = tagsRouter