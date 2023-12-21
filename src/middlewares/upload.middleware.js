const multer = require('multer')
const path = require('path')
// const {v4: uuidv4} = require('uuid')//DOWNLOAD DULU

const storage = (dest, filename) => multer.diskStorage ({
    destination: (req, file, cb) =>{
        cb(null, path.join('uploads',dest))
    },
    filename: (req, file, cb) =>{
        //MENAMBAHKAN .jpg DIBELAKANG NAMA
        const exstensi = {
            'image/jpeg' : '.jpg',
            'image/png' : '.png',
        }
        // //JIKA MENGGUNAKAN NAMA DARI ID USERS
        // if(!filename && req.params.id){
        //     filename = req.params.id
        // }else if(!filename){
        //     filename = new Date().getTime()
        // }

        // //MENGGUNAKAN UUID SEBAGAI NAMA
        // filename = uuidv4()
        // cb(null, `${filename}${exstensi[file.mimetype]}`)

        //MENGGUNAKAN WAKTU SEBAGAI NAMA
        filename = new Date().getTime()
        cb(null, `${filename}${exstensi[file.mimetype]}`)

        //JIKA MENGGUNAKAN NAMA ASLI DARI FILE
        // console.log(file)
        // cb(null, file.originalname)
    }
})

const uploadMiddleware = (type, file) =>{
    const processUpload = multer ({
        storage: storage(type, file),
        //MEMBERIKAN BATAS PADA UKURAN GAMBAR
        limits: {
            fileSize: 3*1024*1024
        },
        //MEMBERIKAN FILTER UNTUK JENIS FILE DAN WAJIB GAMBAR
        fileFilter: (req, file, cb)=>{
            const extensi = ['image/jpeg','image/gif','image/bmp','image/webp','image/png']
            if(!extensi.includes(file.mimetype)){
                cb(new Error('file_issue'), false)
            }else{
                cb(null, true)
            }
        }
    })
    return processUpload
}
module.exports = uploadMiddleware