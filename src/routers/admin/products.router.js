const productRouter = require('express').Router()

// const multer = require('multer')

const productController = require('../../controllers/admin/products.controller')
// const uploadMiddleware = require('../../middlewares/upload.middleware')//

// const upload = multer({dest: 'uploads/'})

productRouter.get('/', productController.getallproducts)

productRouter.get('/:id', productController.getdetailproduct)

productRouter.post('/', productController.createproduct)

productRouter.patch('/:id', productController.updateproduct)

productRouter.delete('/:id', productController.deleteproduct)

module.exports = productRouter