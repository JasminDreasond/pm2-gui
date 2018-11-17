var _ = require('lodash')
var path = require('path')
var Monitor = require('../../lib/monitor')

const fetch = require('node-fetch')
const btoa = require('btoa')

// Progress File
if (process.argv.length > 3) {
    var confFile = process.argv[3]
} else {
    var confFile = path.resolve(path.dirname(path.dirname(__dirname)), './pm2-gui.ini')
}

// Get Config
var tinyMnt = Monitor({
    confFile: confFile
})

// Prepare Discord Info
const monitorDiscord = tinyMnt.options.discord

if ((tinyMnt.options.agent) && (typeof tinyMnt.options.agent.authorization == "string")) {
    var tinyPassword = tinyMnt.options.agent.authorization
}

// Get Discord Config
if ((monitorDiscord) && (typeof monitorDiscord.id == "string")) {
    monitorDiscord.id = monitorDiscord.id.substring(1, monitorDiscord.id.length - 1)
    monitorDiscord.whitelist = require(path.dirname(confFile) + '/discordWhitelist.json')
}

delete tinyMnt

// Authorization
action(function auth(req, res) {

    if (!req._config.agent || (req._config.agent.authorization === req.session['authorization'])) {
        return res.redirect('/')
    }

    // Discord
    if (
        (monitorDiscord) &&
        (typeof monitorDiscord.id == "string") &&
        (typeof monitorDiscord.secret == "string") &&
        (typeof monitorDiscord.redirect == "string")
    ) {

        res.redirect(`https://discordapp.com/oauth2/authorize?client_id=${monitorDiscord.id}&scope=identify&response_type=code&redirect_uri=${monitorDiscord.redirect}`);

    }

    // Default
    else {

        res.render('auth', {
            title: 'Authorization'
        })

    }

})

// Discord

// Callback
const discordCb = {

    // Fail
    fail: function(res, err) {

        if (typeof monitorDiscord.fakeredirect == "string") {
            return res.redirect(monitorDiscord.fakeredirect)
        } else {
            return res.redirect('/discordFail?err=' + encodeURIComponent(err))
        }

    },

    success: function(req, res) {

        if (typeof tinyPassword == "string") { req.session['authorization'] = tinyPassword }
        return res.redirect('/')

    }

}

// Fail
action(async function discordFail(req, res) {

    if ((!req) || (!req.query) || (!req.query.err)) {
        var err = 'Unknow'
    } else if ((typeof req.query.err == "string") && (req.query.err.length < 1000)) {
        var err = req.query.err
    } else {
        var err = 'Long error text...';
    }

    res.render('discordError', {
        title: 'Discord Error: ' + err,
        tinyError: err
    })

});

// Send
action(async function discordAuth(req, res) {

    if (!req._config.agent || (req._config.agent.authorization === req.session['authorization'])) {
        return res.redirect('/')
    }

    if ((!req) || (!req.query) || (!req.query.code)) {
        return discordCb.fail(res, "No Code")
    } else {

        try {

            // Prepare
            const code = req.query.code
            const creds = btoa(`${monitorDiscord.id}:${monitorDiscord.secret}`)

            // Get Token
            const response = await fetch(`https://discordapp.com/api/oauth2/token?grant_type=authorization_code&code=${code}&redirect_uri=${monitorDiscord.redirect}`, {
                method: 'POST',
                headers: {
                    Authorization: `Basic ${creds}`,
                }
            })

            const json = await response.json()

            // Check Token
            if ((json) && ((typeof json.access_token == "string") || (typeof json.access_token == "number"))) {

                const response2 = await fetch(`https://discordapp.com/api/users/@me`, {
                    method: 'GET',
                    headers: {
                        Authorization: `Bearer ${json.access_token}`,
                    }
                })

                const json2 = await response2.json()

                // Check ID
                if ((json2) && (json2.id)) {

                    if ((typeof monitorDiscord.whitelist != "undefined") && (monitorDiscord.whitelist.length > 0)) {

                        for (var i = 0; i < monitorDiscord.whitelist.length; i++) {
                            if (monitorDiscord.whitelist[i] == json2.id) {
                                return discordCb.success(req, res)
                            }
                        }

                    }

                    return discordCb.fail(res, "Restricted Access");

                } else {
                    return discordCb.fail(res, "Incorrect User")
                }

            } else {
                return discordCb.fail(res, "Incorrect Code")
            }

        } catch (e) {
            console.error(e)
            return discordCb.fail(res, "Code Error")
        }

    }

})

// Index
action(function(req, res) {
    if (req._config.agent && (req._config.agent.authorization !== req.session['authorization'])) {
        return res.redirect('/auth')
    }
    var options = _.clone(req._config)
    var q = Monitor.available(_.extend(options, {
        blank: '&nbsp;'
    }))
    var connections = []

    q.choices.forEach(function(c) {
        c.value = Monitor.toConnectionString(Monitor.parseConnectionString(c.value))
        connections.push(c)
    })
    res.render('index', {
        title: 'Monitor',
        connections: connections,
        readonly: !!req._config.readonly
    })
})

// API
action(function auth_api(req, res) { // eslint-disable-line camelcase
    if (!req._config.agent || !req._config.agent.authorization) {
        return res.json({
            error: 'Can not found agent[.authorization] config, no need to authorize!'
        })
    }
    if (!req.query || !req.query.authorization) {
        return res.json({
            error: 'Authorization is required!'
        })
    }

    if (req._config.agent && req.query.authorization === req._config.agent.authorization) {
        req.session['authorization'] = req.query.authorization
        return res.json({
            status: 200
        })
    }
    return res.json({
        error: 'Failed, authorization is incorrect.'
    })
})