let cheerio = require('cheerio')
let request = require('request')
let config = require('./config')
let wget = require('node-wget')
let url = require('url')
let path = require('path')

let toBeExported = {
    findSuspiciousFile:function(){
        return new Promise((resolve, reject)=>{
            request(config.url,function (error,response,body) {
                if(error)
                {
                    reject(error)
                }else
                {
                    let $ = cheerio.load(body)
                    let tempFileSelector = `[src$='${config.suspiciousFile}']`
                    let $theNode = $(tempFileSelector).first()
                    let src = $theNode.attr('src')
                    resolve(src)
                }
            })
        })
    },
    downloadSuspiciousFile:function(src) {
        if(/^\/\//.test(src))
        {
            let tempProtocol = url.parse(config.url).protocol
            src = `${tempProtocol}${src}`
        }
        else if(!src.startsWith('http://') && !src.startsWith('https://'))
        {
            let urlObj = url.parse(config.url)
            let tempHost = urlObj.host
            let tempProtocol = urlObj.protocol
            src = `${tempProtocol}//${tempHost}${src}`
        }
        return new Promise((resolve, reject) => {
            wget(
                {
                    url: src,
                    dest: 'downloaded/'
                },
                function (error, response, body) {
                    if (error) {
                        reject(error)
                    } else {
                        resolve(response.filepath)
                    }
                }
            )
        })
    }
}

module.exports = toBeExported