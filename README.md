# goodsoup
![goodsoup.jpeg](goodsoup.jpeg)

## Usage
- `ddev ssh`
- `vendor/bin/goodsoup.sh`

## How to create the cyclonedx-npm standalone executable
1. `nvm use`
2. `git clone https://github.com/CycloneDX/cyclonedx-node-npm.git vendor-tools/cyclonedx-npm`
2. `cd vendor-tools/cyclonedx-npm`
3. Add the following to the `package.json` file:
```json
"pkg": {
    "assets": [
      "package.json",
      "node_modules/**/*"
    ]
  }
```
4. `npm install`
5. `pkg . -t node18-linux --output dist/cyclonedx-npm`
6. Move the file from `dist/cyclonedx-npm` to the `src` directory
7. Delete the `vendor-tools` directory