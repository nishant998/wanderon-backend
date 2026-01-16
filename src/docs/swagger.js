const path = require("path");
const swaggerJSDoc = require("swagger-jsdoc");

const definition = {
  openapi: "3.0.3",
  info: {
    title: "WanderOn Secure Auth API",
    version: "1.0.0",
    description:
      "Secure authentication system (register/login) using JWT + HttpOnly cookies.",
  },
  servers: [
    { url: "http://localhost:4000", description: "Local" },
    { url: "https://wanderon-backend-xpbk.onrender.com", description: "Production" },
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
    schemas: {
      RegisterRequest: {
        type: "object",
        required: ["email", "username", "password"],
        properties: {
          email: { type: "string", example: "user@example.com" },
          username: { type: "string", example: "nishant" },
          password: { type: "string", example: "StrongPass1" },
        },
      },
      LoginRequest: {
        type: "object",
        required: ["email", "password"],
        properties: {
          email: { type: "string", example: "user@example.com" },
          password: { type: "string", example: "StrongPass1" },
        },
      },
      UserResponse: {
        type: "object",
        properties: {
          id: { type: "string", example: "65b123abc123abc123abc123" },
          email: { type: "string", example: "user@example.com" },
          username: { type: "string", example: "nishant" },
        },
      },
      ApiError: {
        type: "object",
        properties: {
          message: { type: "string", example: "Invalid credentials" },
        },
      },
      ValidationError: {
        type: "object",
        properties: {
          message: { type: "string", example: "Validation error" },
          errors: {
            type: "array",
            items: {
              type: "object",
              properties: {
                path: { type: "string", example: "email" },
                message: { type: "string", example: "Invalid email" },
              },
            },
          },
        },
      },
    },
  },
};

const options = {
  definition, 
  apis: [path.join(__dirname, "..", "routes", "*.js")],
};

const swaggerSpec = swaggerJSDoc(options);

module.exports = { swaggerSpec };
