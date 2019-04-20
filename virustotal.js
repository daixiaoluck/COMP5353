let analysis = require('./analysis')
let path = require('path')
let fs = require('fs')

let express = require('express')
let app = express()
let portNumber = 3000
app.set('port',portNumber)
app.use('/',async function(req,res){
    try
    {
        let src = await analysis.findSuspiciousFile()
        if(!src)
        {
            res.type('text/plain')
            res.send('Didn\'t find injected files.')
            return
        }
        let downloadedFilePath = await analysis.downloadSuspiciousFile(src)
        res.type('text/plain')
        res.send('The malicious JavaScript file has been downloaded.')
    }catch(exception)
    {
        console.error(exception)
    }
})
app.use(function(req,res){
    res.type('text/plain')
    res.status(404)
    res.send('404 - Not Found')
})
app.use(function(err,req,res,next){
    console.error(err.stack)
    res.type('text/plain')
    res.status(500)
    res.send('500 - Server Error')
})
app.listen(portNumber,function(){
    console.log('Click http://localhost:' + portNumber)
})