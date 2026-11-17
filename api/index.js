// Vercel serverless entry point. The Express app lives in ../server.js;
// Vercel runs this file as a function (see vercel.json, which routes all
// paths here). Requiring server.js must NOT start a listener — server.js
// only listens when run directly with `node server.js`.
module.exports = require('../server');
