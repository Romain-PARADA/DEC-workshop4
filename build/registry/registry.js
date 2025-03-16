"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.launchRegistry = launchRegistry;
const body_parser_1 = __importDefault(require("body-parser"));
const express_1 = __importDefault(require("express"));
const config_1 = require("../config");
async function launchRegistry() {
    const _registry = (0, express_1.default)();
    _registry.use(express_1.default.json());
    _registry.use(body_parser_1.default.json());
    const nodes = [];
    _registry.get("/status", (req, res) => {
        res.send('live');
    });
    _registry.post("/registerNode", (req, res) => {
        const { nodeId, pubKey, privateKey } = req.body;
        nodes.push({ nodeId, pubKey, privateKey });
        res.json({ success: true });
    });
    _registry.get("/getNodeRegistry", (req, res) => {
        const publicNodes = nodes.map(({ nodeId, pubKey }) => ({ nodeId, pubKey }));
        res.json({ nodes: publicNodes });
    });
    _registry.get("/getPrivateKey/:nodeId", (req, res) => {
        const nodeId = parseInt(req.params.nodeId);
        const node = nodes.find(n => n.nodeId === nodeId);
        if (!node || !node.privateKey) {
            res.status(404).json({ error: "Private key not found" });
            return;
        }
        res.json({ result: node.privateKey });
    });
    const server = _registry.listen(config_1.REGISTRY_PORT, () => {
        console.log(`registry is listening on port ${config_1.REGISTRY_PORT}`);
    });
    return server;
}
