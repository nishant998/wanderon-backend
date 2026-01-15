const { z } = require("zod");

const registerSchema = z.object({
  email: z.string().email(),
  username: z.string().min(2).max(40),
  password: z
    .string()
    .min(8)
    .max(72)
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/, "Password must include uppercase, lowercase, and a number"),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(72),
});

module.exports = { registerSchema, loginSchema };
