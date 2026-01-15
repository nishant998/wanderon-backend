require("dotenv").config();
const { connectDB } = require("./config/db");
const { app } = require("./app");

(async () => {
  await connectDB();
  const port = process.env.PORT || 4000;
  app.listen(port, () => console.log(`API running on http://localhost:${port}`));
})();
