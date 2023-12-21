const costumerRouter = require('express').Router()

costumerRouter.use('/users', require('./users.router'))

costumerRouter.use('/products', require('./products.router'))

costumerRouter.use('/productSize', require('./productSize.router'))

costumerRouter.use('/productVariant', require('./productVariant.router'))

costumerRouter.use('/tags', require('./tags.router'))

costumerRouter.use('/productTags', require('./productTags.router'))

costumerRouter.use('/productRatings', require('./productRatings.router'))

costumerRouter.use('/categories', require('./categories.router'))

costumerRouter.use('/productCategories', require('./productCategories.router'))

costumerRouter.use('/promo', require('./promo.router'))

costumerRouter.use('/orders', require('./orders.router'))

costumerRouter.use('/orderDetails', require('./orderDetails.router'))

costumerRouter.use('/message', require('./message.router'))

module.exports = costumerRouter