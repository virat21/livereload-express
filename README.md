# Live Reload Express 🚀

add live reload to your expressjs project. this makes your development less clicky and less `F5` presses

Usage
```
const express = require("express");
const app = express();
const port = 3000;
let LiveReloadExpress = require("../index")(app);

app.use(LiveReloadExpress.static("public"));

LiveReloadExpress.listen(port, () =>
  console.log(
    `Example app listening on port ${port}!`
  )
);
```