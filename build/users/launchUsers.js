"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.launchUsers = launchUsers;
const user_1 = require("./user");
async function launchUsers(n) {
    const promises = [];
    for (let index = 0; index < n; index++) {
        const newPromise = (0, user_1.user)(index);
        promises.push(newPromise);
    }
    const servers = await Promise.all(promises);
    return servers;
}
