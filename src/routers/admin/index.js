const adminRouter = require('express').Router()

adminRouter.use('/users', require('./users.router'))

adminRouter.use('/products', require('./products.router'))

adminRouter.use('/productSize', require('./productSize.router'))

adminRouter.use('/productVariant', require('./productVariant.router'))

adminRouter.use('/tags', require('./tags.router'))

adminRouter.use('/productTags', require('./productTags.router'))

adminRouter.use('/productRatings', require('./productRatings.router'))

adminRouter.use('/categories', require('./categories.router'))

adminRouter.use('/productCategories', require('./productCategories.router'))

adminRouter.use('/promo', require('./promo.router'))

adminRouter.use('/orders', require('./orders.router'))

adminRouter.use('/orderDetails', require('./orderDetails.router'))

adminRouter.use('/message', require('./message.router'))

module.exports = adminRouter