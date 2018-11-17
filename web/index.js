var express = require('express')
var session = require('express-session')
var path = require('path')
var http = require('http')
var https = require('https')
var fs = require('fs')
var router = require('../lib/util/router')
var frameguard = require('frameguard')

module.exports = runServer

function runServer(options) {

    var app = express()
    app.set('view engine', 'jade')
    app.set('views', path.join(__dirname, 'templates/views'))
    app.use(express.static(path.join(__dirname, 'public')))
    app.use(frameguard({ action: 'sameorigin' }))
    app.use(session({
        secret: 'pm2@gui',
        resave: false,
        saveUninitialized: true
    }))
    if (options.middleware) {
        app.use(options.middleware)
    }
    router(app)

    if ((options.https) && ((typeof options.https.port == "string") || (typeof options.https.port == "number")) && (typeof options.https.cert == "string") && (typeof options.https.key == "string")) {

        try {
            var server = https.Server({ key: fs.readFileSync(options.https.key, 'utf8'), cert: fs.readFileSync(options.https.cert, 'utf8') }, app)
            server.listen(options.https.port)
        } catch (e) {
            var server = http.Server(app)
            server.listen(options.port)
            console.error(e);
        }

    } else {
        var server = http.Server(app)
        server.listen(options.port)
    }

    return server

}