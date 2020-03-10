# Live Reload Express 🚀

add live reload to your expressjs project. this makes your development less refresh commands and less `F5` presses

**Step 1**
```
npm i livereload-express
```

**Step 2**
```
const express = require("express");
const app = express();
const port = 3000;
let LiveReloadExpress = require("livereload-express")(app);

app.use(LiveReloadExpress.static("public"));

LiveReloadExpress.listen(port, () =>
  console.log(
    `Example app listening on port ${port}!`
  )
);
```

**TODO 💻**

1. ~~Live Reload HTML change~~
2. Live Reload JS change
3. Live Reload CSS change