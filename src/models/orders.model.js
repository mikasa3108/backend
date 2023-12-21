const db = require('../lib/db.lib')

exports.findAll = async ()=> {
    const sql = `SELECT * FROM "orders"`
    const values = []
    const{rows} = await db.query(sql, values)
    return rows
}

exports.findOne = async (id)=> {
    const sql = 'SELECT * FROM "orders" WHERE id = $1'
    const values = [id]
    const{rows} = await db.query(sql, values)
    return rows
}

exports.create = async (data)=> {
    const sql = `INSERT INTO "orders"
    ("userId", "orderNumber", "promoId", "total", "taxAmount", "status", "deliveryAddress", "fullName", "email")
    VALUES
    ($1,$2,$3,$4,$5,$6,$7,$8,$9)
    RETURNING *`
    const values = [data.userId, data.orderNumber, data.promoId, data.total, data.taxAmount, data.status, data.deliveryAddress, data.fullName, data.email]
    const{rows} = await db.query(sql, values)
    return rows[0]
}

exports.update = async (data, id)=> {
    // const sql = `UPDATE "orders" 
    // SET "total" = $1, "status" = $2
    // WHERE "id" = $3
    // RETURNING *`
    // const values = [data.total,data.status,id]
    // const{rows} = await db.query(sql, values)
    // return rows[0]
    const key = []
    const values = []
    values.push(parseInt(id))
    for(let item in data){
        values.push(data[item])
        key.push(`"${item}"=$${values.length}`)
    }
    const sql = `UPDATE "orders"
    SET ${key.join(', ')}, "updated_At" = now() 
    WHERE id = $1
    RETURNING*`
    const{rows} = await db.query(sql, values)
    return rows[0]
}

exports.delete = async (id)=> {
    const sql = `DELETE FROM "orders"
    WHERE "id" = $1
    RETURNING *`
    const values = [id]
    const{rows} = await db.query(sql, values)
    return rows[0]
}