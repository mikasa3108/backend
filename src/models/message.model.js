const db = require('../lib/db.lib')

exports.findAll = async ()=> {
    const sql = `SELECT * FROM "message"`
    const values = []
    const{rows} = await db.query(sql, values)
    return rows
}

exports.findOne = async (id)=> {
    const sql = 'SELECT * FROM "message" WHERE id = $1'
    const values = [id]
    const{rows} = await db.query(sql, values)
    return rows
}

exports.create = async (data)=> {
    const sql = `INSERT INTO "message"
    ("recipientId", "senderId", "text")
    VALUES
    ($1,$2,$3)
    RETURNING *`
    const values = [data.recipientId, data.senderId, data.text]
    const{rows} = await db.query(sql, values)
    return rows[0]
}

exports.update = async (data, id)=> {
    const sql = `UPDATE "message" 
    SET "senderId" = $1, "text" = $2
    WHERE "id" = $3
    RETURNING *`
    const values = [data.senderId,data.text,id]
    const{rows} = await db.query(sql, values)
    return rows[0]
}

exports.delete = async (id)=> {
    const sql = `DELETE FROM "message"
    WHERE "id" = $1
    RETURNING *`
    const values = [id]
    const{rows} = await db.query(sql, values)
    return rows[0]
}