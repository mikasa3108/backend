const db = require('../lib/db.lib')

exports.findAll = async ()=> {
    const sql = `SELECT * FROM users
        ORDER BY "id" ASC`
    const values = []
    const{rows} = await db.query(sql, values)
    return rows
}

exports.findOne = async (id)=> {
    const sql = `SELECT * FROM users WHERE "id" = $1`
    const values = [id]
    const{rows} = await db.query(sql, values)
    return rows
}

exports.findOneByEmail = async (email)=> {
    const sql = `SELECT * FROM users WHERE "email" = $1`
    const values = [email]
    const{rows} = await db.query(sql, values)
    return rows[0]
}

exports.create = async (data)=> {
    const sql = `INSERT INTO "users"
    ("fullName","email","password","address","picture","phoneNumber","role")
    VALUES
    ($1,$2,$3,$4,$5,$6,$7)
    RETURNING *`
    const values = [data.fullName, data.email, data.password, data.address, data.picture, data.phoneNumber, data.role]
    const{rows} = await db.query(sql, values)
    return rows[0]
}

exports.update = async (data, id)=> {
    // const sql = `UPDATE "users" 
    // SET "password" = $1
    // WHERE "id" = $2
    // RETURNING *`
    // const values = [data.password,id]
    // const{rows} = await db.query(sql, values)
    // return rows[0]

    const key = []
    const values = []
    values.push(parseInt(id))
    for(let item in data){
        values.push(data[item])
        key.push(`"${item}"=$${values.length}`)
    }
    const sql = `UPDATE "users"
    SET ${key.join(', ')}, "updated_At" = now() 
    WHERE id = $1
    RETURNING*`
    const{rows} = await db.query(sql, values)
    return rows[0]
}

exports.delete = async (id)=> {
    const sql = `DELETE FROM "users"
    WHERE "id" = $1
    RETURNING *`
    const values = [id]
    const{rows} = await db.query(sql, values)
    return rows[0]
}