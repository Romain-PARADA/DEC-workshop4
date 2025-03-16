import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, exportPubKey, rsaDecrypt, exportPrvKey } from "../crypto";
import { symDecrypt } from "../crypto";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());
  
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  // Générer une paire de clés pour ce routeur
  const keyPair = await generateRsaKeyPair();
  const publicKey = await exportPubKey(keyPair.publicKey);

  // Enregistrer le nœud auprès du registry
  await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ 
      nodeId, 
      pubKey: publicKey,
      privateKey: await exportPrvKey(keyPair.privateKey) 
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
    const privateKey = await exportPrvKey(keyPair.privateKey);
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
      const symKey = await rsaDecrypt(encryptedSymKey, keyPair.privateKey);
      
      // Déchiffrer le message avec la clé symétrique
      const decrypted = await symDecrypt(symKey, encryptedMessage);
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
    } catch (error) {
      console.error("Error processing message:", error);
      res.status(500).send("error");
    }
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}