"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.simpleOnionRouter = simpleOnionRouter;
const body_parser_1 = __importDefault(require("body-parser"));
const express_1 = __importDefault(require("express"));
const config_1 = require("../config");
const crypto_1 = require("../crypto");
const crypto_2 = require("../crypto");
async function simpleOnionRouter(nodeId) {
    const onionRouter = (0, express_1.default)();
    onionRouter.use(express_1.default.json());
    onionRouter.use(body_parser_1.default.json());
    let lastReceivedEncryptedMessage = null;
    let lastReceivedDecryptedMessage = null;
    let lastMessageDestination = null;
    // Générer une paire de clés pour ce routeur
    const keyPair = await (0, crypto_1.generateRsaKeyPair)();
    const publicKey = await (0, crypto_1.exportPubKey)(keyPair.publicKey);
    // Enregistrer le nœud auprès du registry
    await fetch(`http://localhost:${config_1.REGISTRY_PORT}/registerNode`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            nodeId,
            pubKey: publicKey,
            privateKey: await (0, crypto_1.exportPrvKey)(keyPair.privateKey)
        })
    });
    onionRouter.get("/status", (req, res) => {
        res.send("live");
    });
    onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
        res.json({ result: lastReceivedEncryptedMessage });
    });
    onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
        res.json({ result: lastReceivedDecryptedMessage });
    });
    onionRouter.get("/getLastMessageDestination", (req, res) => {
        res.json({ result: lastMessageDestination });
    });
    onionRouter.get("/getPrivateKey", async (req, res) => {
        const privateKey = await (0, crypto_1.exportPrvKey)(keyPair.privateKey);
        res.json({ result: privateKey });
    });
    onionRouter.post("/message", async (req, res) => {
        const { message } = req.body;
        lastReceivedEncryptedMessage = message;
        try {
            // Extraire la clé symétrique chiffrée (344 premiers caractères)
            const encryptedSymKey = message.substring(0, 344);
            const encryptedMessage = message.substring(344);
            // Déchiffrer la clé symétrique avec la clé privée RSA
            const symKey = await (0, crypto_1.rsaDecrypt)(encryptedSymKey, keyPair.privateKey);
            // Déchiffrer le message avec la clé symétrique
            const decrypted = await (0, crypto_2.symDecrypt)(symKey, encryptedMessage);
            lastReceivedDecryptedMessage = decrypted;
            // Les 10 premiers caractères sont la destination
            const destinationStr = decrypted.substring(0, 10);
            lastMessageDestination = parseInt(destinationStr);
            // Le reste est le message pour la destination
            const messageForDestination = decrypted.substring(10);
            // Transmettre le message à la destination
            if (lastMessageDestination) {
                await fetch(`http://localhost:${lastMessageDestination}/message`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: messageForDestination })
                });
            }
            res.send("success");
        }
        catch (error) {
            console.error("Error processing message:", error);
            res.status(500).send("error");
        }
    });
    const server = onionRouter.listen(config_1.BASE_ONION_ROUTER_PORT + nodeId, () => {
        console.log(`Onion router ${nodeId} is listening on port ${config_1.BASE_ONION_ROUTER_PORT + nodeId}`);
    });
    return server;
}
