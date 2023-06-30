## Weavechain Javascript API

[https://weavechain.com](https://weavechain.com): Layer-0 For Data

#### Packages

- [@weavechain/weave-js-api](https://github.com/weavechain/weave-js-api/tree/master/packages/weave-js-api): Javascript API
- [@weavechain/weave-react-api](https://github.com/weavechain/weave-js-api/tree/master/packages/weave-react-api): React Native API

#### How to install

```sh
npm install @weavechain/weave-js-api --save
```

or

```sh
yarn add @weavechain/weave-js-api
```


#### Data read sample

```js
import { WeaveAPI, WeaveHelper } from "@weavechain/weave-js-api"

const [ pub, pvk ] = WeaveHelper.generateKeys();
console.log("Public key: ", pub);
console.log("Private key: ", pvk);

const node = "https://public.weavechain.com:443/92f30f0b6be2732cb817c19839b0940c";
const organization = "weavedemo";
const scope = "shared";
const table = "directory";
const encrypted = node.startsWith("http://");

const cfg = WeaveHelper.getConfig(node, pub, pvk, encrypted)

const nodeApi = new WeaveAPI().create(cfg);
await nodeApi.init();

const session = await nodeApi.login(organization, pub, scope || "*");

nodeApi.read(session, scope, table, null, WeaveHelper.Options.READ_DEFAULT_NO_CHAIN).then((r, ex) => {
    if (ex) {
        console.log("Failed", ex);
    } else {
        console.log(r);
    }
});

```

#### Docs

[https://docs.weavechain.com](https://docs.weavechain.com)