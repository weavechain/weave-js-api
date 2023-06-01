import { copyFileSync, rmSync, existsSync, mkdirSync } from "fs";
import { copySync } from "fs-extra";
import { execSync } from "child_process";

console.log("Cleaning...");
rmSync("dist", { recursive: true, force: true });

console.log("Copying files...");

const dir = './dist';
if (!existsSync(dir)){
    mkdirSync(dir);
}

const libDir = dir + "/lib";
if (!existsSync(libDir)){
    mkdirSync(libDir);
}

//copyFileSync("./README.md", "./dist/README.md");
copyFileSync("./package.json", dir + "/package.json");
copySync("./lib/", libDir);

console.log("Done.");
