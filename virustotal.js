let analysis = require('./analysis')
let path = require('path')
let fs = require('fs')

let vt = require('node-virustotal')
let con = vt.MakePublicConnection()
con.setKey('e2513a75f92a4169e8a47b4ab1df757f83ae45008b4a8a49903450c8402add4d')

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
        let nameToSubmit = path.parse(downloadedFilePath).base
        con.submitFileForAnalysis(nameToSubmit, "application/javascript", fs.readFileSync(downloadedFilePath), function(data){
            res.type('text/plain')
            res.send('The scan result: ' + data.permalink)
        }, function(mistake){
            throw mistake
        })
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