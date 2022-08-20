const bcrypt = require('./libs/bcryptjs')
const jwt = require('./libs/jsonwebtoken')
const Logger = require('./Logger')
const https = require('https')
const User = require('./objects/user/User')

class Auth {
  constructor(db) {
    this.db = db

    this.user = null
  }

  get username() {
    return this.user ? this.user.username : 'nobody'
  }

  get users() {
    return this.db.users
  }

  cors(req, res, next) {
    res.header('Access-Control-Allow-Origin', '*')
    res.header("Access-Control-Allow-Methods", 'GET, POST, PATCH, PUT, DELETE, OPTIONS')
    res.header('Access-Control-Allow-Headers', '*')
    // TODO: Make sure allowing all headers is not a security concern. It is required for adding custom headers for SSO
    // res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Accept-Encoding, Range, Authorization")
    res.header('Access-Control-Allow-Credentials', true)
    if (req.method === 'OPTIONS') {
      res.sendStatus(200)
    } else {
      next()
    }
  }

  async initTokenSecret() {
    if (process.env.TOKEN_SECRET) { // User can supply their own token secret
      Logger.debug(`[Auth] Setting token secret - using user passed in TOKEN_SECRET env var`)
      this.db.serverSettings.tokenSecret = process.env.TOKEN_SECRET
    } else {
      Logger.debug(`[Auth] Setting token secret - using random bytes`)
      this.db.serverSettings.tokenSecret = require('crypto').randomBytes(256).toString('base64')
    }
    await this.db.updateServerSettings()

    // New token secret creation added in v2.1.0 so generate new API tokens for each user
    if (this.db.users.length) {
      for (const user of this.db.users) {
        user.token = await this.generateAccessToken({ userId: user.id, username: user.username })
        Logger.warn(`[Auth] User ${user.username} api token has been updated using new token secret`)
      }
      await this.db.updateEntities('user', this.db.users)
    }
  }

  async authMiddleware(req, res, next) {
    var token = null

    // If using a get request, the token can be passed as a query string
    if (req.method === 'GET' && req.query && req.query.token) {
      token = req.query.token
    } else {
      const authHeader = req.headers['authorization']
      token = authHeader && authHeader.split(' ')[1]
    }

    if (token == null) {
      Logger.error('Api called without a token', req.path)
      return res.sendStatus(401)
    }

    var user = await this.verifyToken(token)
    if (!user) {
      Logger.error('Verify Token User Not Found', token)
      return res.sendStatus(404)
    }
    if (!user.isActive) {
      Logger.error('Verify Token User is disabled', token, user.username)
      return res.sendStatus(403)
    }
    req.user = user
    next()
  }

  hashPass(password) {
    return new Promise((resolve) => {
      bcrypt.hash(password, 8, (err, hash) => {
        if (err) {
          Logger.error('Hash failed', err)
          resolve(null)
        } else {
          resolve(hash)
        }
      })
    })
  }

  generateAccessToken(payload) {
    return jwt.sign(payload, global.ServerSettings.tokenSecret);
  }

  authenticateUser(token) {
    return this.verifyToken(token)
  }

  verifyToken(token) {
    return new Promise((resolve) => {
      jwt.verify(token, global.ServerSettings.tokenSecret, (err, payload) => {
        if (!payload || err) {
          Logger.error('JWT Verify Token Failed', err)
          return resolve(null)
        }
        var user = this.users.find(u => u.id === payload.userId && u.username === payload.username)
        resolve(user || null)
      })
    })
  }

  getUserLoginResponsePayload(user, feeds) {
    return {
      user: user.toJSONForBrowser(),
      userDefaultLibraryId: user.getDefaultLibraryId(this.db.libraries),
      serverSettings: this.db.serverSettings.toJSONForBrowser(),
      feeds,
      Source: global.Source
    }
  }

  async doAyncRequest(options, data) {
    return new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        res.setEncoding('utf8')
        let responseBody = ''

        res.on('data', (chunk) => {
          responseBody += chunk
        });

        res.on('end', () => {
          resolve(res.statusCode)
        });
      });

      req.on('error', (err) => {
        resolve(res.statusCode)
      });

      req.write(data)
      req.end();
    });
  }

  async loginJellyfin(req, res) {
    var username = (req.body.username || '').toLowerCase()
    var password = req.body.password || ''
    var data = {"Username": username, "Pw": password}

    var options = {
      host: process.env.JELLYFIN,
      port: 443,
      path: '/Users/authenticatebyname',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(JSON.stringify(data)),
        'x-emby-authorization': 'MediaBrowser Client="Sapd Audiobookconnector", Device="Sapds-Audiobookconnector", DeviceId="audiobooks-'+encodeURIComponent(username)+'", Version="1.0.0"'
      }
    };

    var statuscode = await this.doAyncRequest(options, JSON.stringify(data))
    console.log(statuscode)

    if (statuscode === 401) {
      return res.status(401).send('Invalid user or password')
    } else if (statuscode != 200) {
      return res.status(401).send('Jellyfin connector error')
    }

    // success

    // check for user
    var user = this.users.find(u => u.username.toLowerCase() === username)

    if (!user) {
      let token = await this.generateAccessToken({ userId: username, username: username })

      const newUser = new User({
        id: username,
        type: 'user',
        username,
        pash: 'PoweredBySapd',
        token,
        isActive: true,
        isLocked: false,
        createdAt: Date.now()
      })
      this.db.insertEntity('user', newUser)

      res.json(this.getUserLoginResponsePayload(newUser))

    }
    else {
      res.json(this.getUserLoginResponsePayload(user))
    }
  }

  async login(req, res, feeds) {
    var username = (req.body.username || '').toLowerCase()
    var password = req.body.password || ''

    if (username === 'root') {
      var user = this.users.find(u => u.username.toLowerCase() === username)

      if (!user || !user.isActive) {
        Logger.debug(`[Auth] Failed login attempt ${req.rateLimit.current} of ${req.rateLimit.limit}`)
        if (req.rateLimit.remaining <= 2) {
          return res.status(401).send(`Invalid user or password (${req.rateLimit.remaining === 0 ? '1 attempt remaining' : `${req.rateLimit.remaining + 1} attempts remaining`})`)
        }
        return res.status(401).send('Invalid user or password')
      }

      // Check passwordless root user
      if (user.id === 'root' && (!user.pash || user.pash === '')) {
        if (password) {
          return res.status(401).send('Invalid root password (hint: there is none)')
        } else {
          return res.json(this.getUserLoginResponsePayload(user, feeds))
        }
      }

      // Check password match
      var compare = await bcrypt.compare(password, user.pash)
      if (compare) {
        res.json(this.getUserLoginResponsePayload(user, feeds))
      } else {
        Logger.debug(`[Auth] Failed login attempt ${req.rateLimit.current} of ${req.rateLimit.limit}`)
        if (req.rateLimit.remaining <= 2) {
          Logger.error(`[Auth] Failed login attempt for user ${user.username}. Attempts: ${req.rateLimit.current}`)
          return res.status(401).send(`Invalid user or password (${req.rateLimit.remaining === 0 ? '1 attempt remaining' : `${req.rateLimit.remaining + 1} attempts remaining`})`)
        }
        return res.status(401).send('Invalid user or password')
      }
    }
    else {
      return this.loginJellyfin(req, res)
    }
  }

  // Not in use now
  lockUser(user) {
    user.isLocked = true
    return this.db.updateEntity('user', user).catch((error) => {
      Logger.error('[Auth] Failed to lock user', user.username, error)
      return false
    })
  }

  comparePassword(password, user) {
    if (user.type === 'root' && !password && !user.pash) return true
    if (!password || !user.pash) return false
    return bcrypt.compare(password, user.pash)
  }

  async userChangePassword(req, res) {
    var { password, newPassword } = req.body
    newPassword = newPassword || ''
    var matchingUser = this.users.find(u => u.id === req.user.id)

    // Only root can have an empty password
    if (matchingUser.type !== 'root' && !newPassword) {
      return res.json({
        error: 'Invalid new password - Only root can have an empty password'
      })
    }

    var compare = await this.comparePassword(password, matchingUser)
    if (!compare) {
      return res.json({
        error: 'Invalid password'
      })
    }

    var pw = ''
    if (newPassword) {
      pw = await this.hashPass(newPassword)
      if (!pw) {
        return res.json({
          error: 'Hash failed'
        })
      }
    }

    matchingUser.pash = pw
    var success = await this.db.updateEntity('user', matchingUser)
    if (success) {
      res.json({
        success: true
      })
    } else {
      res.json({
        error: 'Unknown error'
      })
    }
  }
}
module.exports = Auth