import http from 'http';
import { WebSocketServer } from 'ws';
import crypto from 'crypto';
import url from 'url'
import fs from 'fs';
import path from 'path';
import { MongoClient } from 'mongodb'

const VER = '0.1.0';
const SERV_NAME = 'Secure Chats Server';
const PROT_VER = '0.1.0';
const PROT_NAME = 'Secure Chats Protocol';
const config = JSON.parse(fs.readFileSync('config.json', 'utf8'));

const dbClient = new MongoClient(`mongodb://${encodeURIComponent(config.db.user)}:${encodeURIComponent(config.db.password)}@${config.db.host}:${config.db.port}/`, {
    tls: true,
    tlsInsecure: true,
})
const db = dbClient.db(config.db.database);

function sendResponse(ok: boolean, data: any, error?: string) {
    let res: any = {
        ok: ok,
        body: data
    }
    if (!ok) {
        res.error = error
    }
    return JSON.stringify(res)
}

function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

const httpServer = http.createServer((req, res) => {
    const clearUrl = req.url?.split('?')[0];
    const args = url.parse(req.url || "", true).query;
    let ip = req.socket.remoteAddress
    if (ip == "::1") {
        ip = "127.0.0.1"
    }
    if (req.headers['x-forwarded-for'] != undefined && config.trustedProxies.includes(ip)) {
        ip = req.headers['x-forwarded-for'] as string;
    }
    if (clearUrl == "/version") {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(sendResponse(true, {
            protocol: PROT_NAME,
            protocolVersion: PROT_VER,
            serverVersion: VER,
            serverName: SERV_NAME
        }))
    } else if (clearUrl == "/client") {
        res.writeHead(301, { 'Location': '/client/' });
        res.end();
    } else if (clearUrl?.startsWith("/client/")) {
        let pathRemaining = clearUrl.replace("/client/", "");
        let file = `./client/${path.normalize(pathRemaining)}`;
        if (file == "./client/.") {
            file = "./client/index.html";
        }
        if (!fs.existsSync(file)) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(sendResponse(false, null, "Not Found"));
            return;
        }
        let content = fs.readFileSync(file, 'utf8');
        if (file.endsWith(".html")) {
            res.writeHead(200, { 'Content-Type': 'text/html', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".js")) {
            res.writeHead(200, { 'Content-Type': 'application/javascript', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else if (file.endsWith(".css")) {
            res.writeHead(200, { 'Content-Type': 'text/css', 'cache-control': 'max-age=86400' });
            res.end(content);
        } else {
            res.writeHead(200, { 'Content-Type': 'text/text', 'cache-control': 'max-age=86400' });
            res.end(content);
        }
    } else if (clearUrl == "/api/register" && req.method === 'POST') {
        let body = '';
        req.on('data', async (data) => {
            body += data.toString();
        })
        req.on('end', async () => {
            let parsedBody: any;
            try {
                parsedBody = JSON.parse(body);
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid JSON"));
                return;
            }
            if (parsedBody.username == undefined || typeof parsedBody.username != "string" || parsedBody.username.length < 5 || parsedBody.username.length > 32) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid username"));
                return;
            }
            if (parsedBody.password == undefined || typeof parsedBody.password != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid password"));
                return;
            }
            if (parsedBody.privateKey == undefined || typeof parsedBody.privateKey != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid private key"));
                return;
            }
            if (parsedBody.publicKey == undefined || typeof parsedBody.publicKey != "string") {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Invalid public key"));
                return;
            }
            const collection = db.collection("users");
            let existingUser = await collection.findOne({ username: parsedBody.username });
            if (existingUser != null) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(sendResponse(false, null, "Username already exists"));
                return;
            }
            let token: string;
            let check = 0
            while (true) {
                token = generateRandomString(256);
                let existingToken = await collection.findOne({ token: token });
                if (existingToken == null) {
                    break;
                }
                check++;
                if (check > 10) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(sendResponse(false, null, "Could not generate token, please try again later..."));
                    return;
                }
            }
            collection.insertOne({
                username: parsedBody.username,
                password: crypto.createHash('sha256').update(parsedBody.password).digest('hex'),
                privateKey: parsedBody.privateKey,
                publicKey: parsedBody.publicKey,
                createdAt: new Date(),
                lastLogin: new Date(),
                lastIP: ip,
                token: token,
                suspended: false
            })
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(sendResponse(true, {
                username: parsedBody.username,
                token: token
            }));
        })
    } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(sendResponse(false, null, "Not Found"));
    }
});

const wsServer = new WebSocketServer({
    server: httpServer,
    path: '/ws'
})


httpServer.listen(config.port, () => {
    console.log('Server is running on http://localhost:' + config.port);
    console.log(`Secure chats server V${VER}`)
});