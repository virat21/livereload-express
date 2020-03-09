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
