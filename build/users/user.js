"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.user = user;
const body_parser_1 = __importDefault(require("body-parser"));
const express_1 = __importDefault(require("express"));
const config_1 = require("../config");
const crypto_1 = require("../crypto");
async function user(userId) {
    const _user = (0, express_1.default)();
    _user.use(express_1.default.json());
    _user.use(body_parser_1.default.json());
    // Variables pour stocker les messages
    let lastReceivedMessage = null;
    let lastSentMessage = null;
    let lastCircuit = null;
    _user.get("/status", (req, res) => {
        res.send("live");
    });
    _user.get("/getLastReceivedMessage", (req, res) => {
        res.json({ result: lastReceivedMessage });
    });
    _user.get("/getLastSentMessage", (req, res) => {
        res.json({ result: lastSentMessage });
    });
    _user.post("/message", (req, res) => {
        const { message } = req.body;
        lastReceivedMessage = message;
        res.send("success");
    });
    _user.get("/getLastCircuit", (req, res) => {
        res.json({ result: lastCircuit });
    });
    _user.post("/sendMessage", async (req, res) => {
        const { message, destinationUserId } = req.body;
        lastSentMessage = message;
        try {
            // 1. Obtenir le registre des nœuds
            const registryResponse = await fetch(`http://localhost:${config_1.REGISTRY_PORT}/getNodeRegistry`);
            const { nodes } = (await registryResponse.json());
            // 2. Créer un circuit aléatoire de 3 nœuds
            const circuit = nodes
                .sort(() => Math.random() - 0.5)
                .slice(0, 3)
                .map(n => n.nodeId);
            lastCircuit = circuit;
            // 3. Créer une clé symétrique pour chaque nœud
            let finalMessage = message;
            for (let i = circuit.length - 1; i >= 0; i--) {
                const nodeId = circuit[i];
                const node = nodes.find(n => n.nodeId === nodeId);
                if (!node) {
                    throw new Error(`Node ${nodeId} not found in registry`);
                }
                // Créer et exporter la clé symétrique
                const symKey = await (0, crypto_1.createRandomSymmetricKey)();
                const exportedSymKey = await (0, crypto_1.exportSymKey)(symKey);
                // Destination pour ce nœud (prochain nœud ou utilisateur final)
                const nextPort = i === circuit.length - 1
                    ? config_1.BASE_USER_PORT + destinationUserId
                    : config_1.BASE_ONION_ROUTER_PORT + circuit[i + 1];
                const destination = nextPort.toString().padStart(10, '0');
                // Chiffrer le message avec la clé symétrique
                finalMessage = await (0, crypto_1.symEncrypt)(symKey, destination + finalMessage);
                // Chiffrer la clé symétrique avec la clé publique du nœud
                const encryptedSymKey = await (0, crypto_1.rsaEncrypt)(exportedSymKey, node.pubKey);
                // Concaténer la clé et le message
                finalMessage = encryptedSymKey + finalMessage;
            }
            // 4. Envoyer au premier nœud
            const firstNodePort = config_1.BASE_ONION_ROUTER_PORT + circuit[0];
            await fetch(`http://localhost:${firstNodePort}/message`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: finalMessage })
            });
            res.send("success");
        }
        catch (error) {
            console.error('Error sending message:', error);
            res.status(500).send("error");
        }
    });
    const server = _user.listen(config_1.BASE_USER_PORT + userId, () => {
        console.log(`User ${userId} is listening on port ${config_1.BASE_USER_PORT + userId}`);
    });
    return server;
}
