const path = require("path");
const swaggerJSDoc = require("swagger-jsdoc");

const swaggerDefinition = {
  openapi: "3.0.3",
  info: {
    title: "WanderOn Secure Auth API",
    version: "1.0.0",
    description: "Secure authentication system (register/login) using JWT + HttpOnly cookies.",
  },
  servers: [
    {
      url: "https://wanderon-backend-xpbk.onrender.com",
      description: "Production",
    },
    {
      url: "http://localhost:4000",
      description: "Local",
    },
  ],
  tags: [{ name: "Auth", description: "Authentication endpoints" }],
  components: {
    securitySchemes: {
      cookieAuth: {
        type: "apiKey",
        in: "cookie",
        name: "access_token",
        description: "JWT stored in HttpOnly cookie named `access_token`",
      },
    },
    schemas: { /* keep your schemas as-is */ },
  },
};

const options = {
  definition: swaggerDefinition,
  apis: [path.join(__dirname, "..", "routes", "*.js")],
};

const swaggerSpec = swaggerJSDoc(options);

module.exports = { swaggerSpec };
