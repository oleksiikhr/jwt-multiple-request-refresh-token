const jwt = require('jsonwebtoken')
const http = require('http')
const path = require('path')
const url = require('url')
const fs = require('fs')

// We take data with Environment
const jwtTokenExpires = +process.env.JWT_TOKEN_EXPIRES || 5 // seconds
const jwtTokenRefresh = +process.env.JWT_TOKEN_REFRESH || 10 // seconds
const jwtPrivateKey = process.env.JWT_PRIVATE_KEY || 'private-key'
const hostname = process.env.HOSTNAME || '127.0.0.1'
const port = +process.env.PORT || 3000

/**
 * @param {string} login
 * @return {string}
 */
const generateToken = (login) => {
  return jwt.sign({ login }, jwtPrivateKey, { expiresIn: jwtTokenExpires })
}

// Create a node.js server
http.createServer((req, resp) => {
  const parsedUrl = url.parse(req.url, { parseQueryString: true })

  /**
   * Requests from an authorized user come in the following form:
   *    Authorization: Bearer eyJ...
   * @type {string}
   */
  let headerToken = req.headers.authorization
  if (headerToken && headerToken.startsWith('Bearer ')) {
    headerToken = headerToken.slice(7)
  }

  switch (parsedUrl.pathname) {
    /*
     * Simply output the html file through our server
     */
    case '/':
      // We read our index.html file to give it through the server
      const htmlFile = fs.readFileSync(path.resolve(__dirname, 'index.html'))

      resp.setHeader('Content-Type', 'text/html')
      resp.write(htmlFile)
      break
    /*
     * By the received login - we generate a new JWT
     * token and return it to the user
     */
    case '/api/login':
      // Omit user, password, and other checks
      resp.write(JSON.stringify({ message: 'Token Received', content: {
        token: generateToken(parsedUrl.query.login),
        expires: jwtTokenExpires,
        refresh: jwtTokenRefresh
      }}))
      break
    /*
     * Get a new token based on the old one, but which has expired
     */
    case '/api/refresh':
      // Token must be in request HEADER
      if (!headerToken) {
        resp.statusCode = 400
        resp.write(JSON.stringify({ message: 'Token not found', content: null }))
        break
      }

      let decodedToken = null

      try {
        // Turn off errors if the token has expired
        decodedToken = jwt.verify(headerToken, jwtPrivateKey, { ignoreExpiration: true })
      } catch (e) {
        resp.statusCode = 400
        resp.write(JSON.stringify({ message: e.message, content: null }))
        break
      }

      const tokenDate = new Date((decodedToken.exp + jwtTokenRefresh) * 1000)

      // Check the date, if we can still restore the token
      if (tokenDate < new Date()) {
        resp.statusCode = 400
        resp.write(JSON.stringify({ message: 'The time to receive a new token has expired', content: null }))
        break
      }

      // The token goes to the blacklist so that it is impossible
      // to receive a new token several times

      resp.write(JSON.stringify({ message: 'Token Received', content: {
        token: generateToken(decodedToken.login),
        expires: jwtTokenExpires,
        refresh: jwtTokenRefresh
      }}))
      break
    /*
     * Request that requires user authorization
     */
    case '/api/secret':
      try {
        jwt.verify(headerToken, jwtPrivateKey)
        resp.write(JSON.stringify({ message: 'Secret Data Received', content: null }))
      } catch (e) {
        resp.statusCode = 401
        resp.write(JSON.stringify({ message: e.message, content: null }))
      }
      break
    /*
     * Request that does not require user authorization
     */
    case '/api/public':
      resp.write(JSON.stringify({ message: 'Public Data Received', content: null }))
      break
    /*
     * 404 for other pages
     */
    default:
      resp.statusCode = 404
      resp.write('not found')
  }

  resp.end()
})
  .listen(port, hostname, () => {
    console.log(`Server running at http://${hostname}:${port}/`)
  })
