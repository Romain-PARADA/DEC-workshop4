import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import { createRandomSymmetricKey, exportSymKey, symEncrypt, rsaEncrypt } from "../crypto";
import { GetNodeRegistryBody } from "../registry/registry";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  // Variables pour stocker les messages
  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: number[] | null = null;

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
      const registryResponse = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      const { nodes } = (await registryResponse.json()) as GetNodeRegistryBody;

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
        const symKey = await createRandomSymmetricKey();
        const exportedSymKey = await exportSymKey(symKey);
        
        // Destination pour ce nœud (prochain nœud ou utilisateur final)
        const nextPort = i === circuit.length - 1 
          ? BASE_USER_PORT + destinationUserId
          : BASE_ONION_ROUTER_PORT + circuit[i + 1];
        const destination = nextPort.toString().padStart(10, '0');
        
        // Chiffrer le message avec la clé symétrique
        finalMessage = await symEncrypt(symKey, destination + finalMessage);
        
        // Chiffrer la clé symétrique avec la clé publique du nœud
        const encryptedSymKey = await rsaEncrypt(exportedSymKey, node.pubKey);
        
        // Concaténer la clé et le message
        finalMessage = encryptedSymKey + finalMessage;
      }

      // 4. Envoyer au premier nœud
      const firstNodePort = BASE_ONION_ROUTER_PORT + circuit[0];
      await fetch(`http://localhost:${firstNodePort}/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: finalMessage })
      });

      res.send("success");
    } catch (error) {
      console.error('Error sending message:', error);
      res.status(500).send("error");
    }
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}