import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { 
  nodeId: number; 
  pubKey: string;
  privateKey?: string;
};

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
  privateKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  const nodes: Node[] = [];

  _registry.get("/status", (req, res) => {
    res.send('live');
  });

  _registry.post("/registerNode", (req: Request<{}, {}, RegisterNodeBody>, res: Response) => {
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

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
