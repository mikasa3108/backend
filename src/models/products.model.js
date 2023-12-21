const db = require('../lib/db.lib')

exports.findAll = async (keyword='', sortBy, orderBy, page = 1, limit)=> {
    const sort = ['idProduct', 'created_At', 'name','basePrice', 'categoriesName']
    const order = ['asc', 'desc']
    const limitData = limit
    const offset = (page - 1) * limitData
    sortBy = sort.includes(sortBy)? sortBy : 'id'
    orderBy = order.includes(orderBy)? orderBy : 'asc'
    const sql = `SELECT "products"."name" AS "productName","products"."id" "idProduct","image", "basePrice", "categories"."name" AS "categoriesName"
    FROM "products"
    FULL JOIN "productCategories" ON "productCategories"."productId" = "products"."id"
    FULL JOIN "categories" ON "productCategories"."categoryId" = "categories"."id"
    WHERE  "products"."name" ILIKE $1
    ORDER BY "${sortBy}" ${orderBy}
    LIMIT ${limitData} OFFSET ${offset}`
    const values = [`%${keyword}%`]
    const{rows} = await db.query(sql, values)
    return rows
}


exports.countAll = async (keyword='')=>{
    const sql = `SELECT COUNT("id")
    FROM "products"
    WHERE "name" ILIKE $1`
    const values = [`%${keyword}%`]
    const{rows} = await db.query(sql, values)
    return parseInt(rows[0].count)//BANYAKNYA DATA YANG DISIMPAN
}

exports.findOne = async (id)=> {
    const sql = 'SELECT * FROM products WHERE id = $1'
    const values = [id]
    const{rows} = await db.query(sql, values)
    return rows
}

exports.create = async (data)=> {
    const sql = `INSERT INTO "products"
    ("name","description","basePrice","image","discount","isRecommended","stock")
    VALUES
    ($1,$2,$3,$4,$5,$6,$7)
    RETURNING *`
    const values = [data.name, data.description, data.basePrice, data.image, data.picture, data.isRecommended, data.stock]
    const{rows} = await db.query(sql, values)
    return rows[0]
}

exports.update = async (id, data)=> {
    // //MANUAL 1 PER 1
    // const sql = `UPDATE "products" 
    // SET "image" = $1
    // WHERE "id" = $2
    // RETURNING *`
    // const values = [data.image,id]
    // const{rows} = await db.query(sql, values)
    // return rows[0]

    const key = []
    const values = []
    values.push(parseInt(id))
    for(let item in data){
        values.push(data[item])
        key.push(`"${item}"=$${values.length}`)
    }
    const sql = `UPDATE "products"
    SET ${key.join(', ')}, "updated_At" = now() 
    WHERE id = $1
    RETURNING*`
    const{rows} = await db.query(sql, values)
    return rows[0]
}

exports.delete = async (id)=> {
    const sql = `DELETE FROM "products"
    WHERE "id" = $1
    RETURNING *`
    const values = [id]
    const{rows} = await db.query(sql, values)
    return rows[0]
}