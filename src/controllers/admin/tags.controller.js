let tagsModel = require('../../models/tags.model')

exports.getAllTags = async (req, res) => {
    const tags = await tagsModel.findAll()
    return res.json({
        success: true,
        message: 'list all tags',
        result: tags
    })
}

exports.getDetailTags = async (req, res) => {
    const id = parseInt(req.params.id)
    const tags = await tagsModel.findOne(id)
    if (!tags[0]) {
        return res.status(404).json({
            success: false,
            message: 'tags not found'
        })
    }
    return res.json({
        success: true,
        message: 'detail tags',
        result: tags[0]
    })
}

exports.createTags = async (req, res) => {
    const data = req.body
    try {
        const tags = await tagsModel.create(data)
        return res.json({
            success: true,
            message: 'create tags success',
            result: tags
        })
    } catch (err) {
        if (err.code === '23502') {
            return res.status(400).json({
                success: false,
                message: `data cannot be empty`
            })
        }
        console.log(err)
        return res.status(500).json({
            success: false,
            message: 'internal server error'
        })
    }
}

exports.updateTags = async (req, res) => {
    const id = parseInt(req.params.id)
    const data = req.body
    try {
        const tags = await tagsModel.update(data, id)
        return res.json({
            success: true,
            message: 'success',
            result: tags
        })
    } catch (err) {
        return res.status(404).json({
            success: false,
            message: 'tags not found'
        })
    }
}

exports.deleteTags = async (req, res) => {
    const id = parseInt(req.params.id)
    try {
        const tags = await tagsModel.delete(id)
        return res.json({
            success: true,
            message: 'success',
            result: tags
        })
    } catch (err) {
        return res.status(404).json({
            success: false,
            message: 'tags not found'
        })
    }
}