"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.launchNetwork = launchNetwork;
const launchOnionRouters_1 = require("./onionRouters/launchOnionRouters");
const registry_1 = require("./registry/registry");
const launchUsers_1 = require("./users/launchUsers");
async function launchNetwork(nbNodes, nbUsers) {
    // launch node registry
    const registry = await (0, registry_1.launchRegistry)();
    // launch all nodes
    const onionServers = await (0, launchOnionRouters_1.launchOnionRouters)(nbNodes);
    // launch all users
    const userServers = await (0, launchUsers_1.launchUsers)(nbUsers);
    return [registry, ...onionServers, ...userServers];
}
