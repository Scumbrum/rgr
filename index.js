import crypto from "crypto";
import fs from "fs";

class Server {
    certificate = '';
    publicKey = '';

    sessions = {};

    verifyCert(cert) {
        const a = crypto.createPublicKey(cert).export({type:'spki', format:'pem'})

        return a.split('\n').join('') === this.publicKey ? this.publicKey :  null;
    }

    setHelloMessage() {
        console.log('Hello from server');
        return {
            message: 'Hello from server',
            cert: this.certificate
        }
    }

    setPreMaster(preMater) {
        console.log("Premaster: " + preMater)
        const decipher = crypto.createDecipher('aes256', this.publicKey);
        const decrypted = decipher.update(preMater, 'hex', 'utf8') + decipher.final('utf8');
        const newIndex = Object.keys(this.sessions).length
        const sessionKey = `${decrypted}:${newIndex}`
        console.log("Server session key: " + sessionKey)
        this.sessions[sessionKey] = ''
        const cipher = crypto.createCipher('aes256', sessionKey);
        const encrypted = cipher.update('готовий', 'utf8', 'hex') + cipher.final('hex');
        return {
            key: sessionKey,
            message: encrypted
        }
    }

    sendReadyMessage(sessionKey, data) {
        const decipher = crypto.createDecipher('aes256', data.clientKey);
        const decrypted = decipher.update(data.message, 'hex', 'utf8') + decipher.final('utf8');
        console.log(decrypted + ":" + "connected")
        this.sessions[sessionKey] = data.clientKey
        const cipher = crypto.createCipher('aes256', sessionKey);
        const encrypted = cipher.update('прийнято', 'utf8', 'hex') + cipher.final('hex');
        return {
            message: encrypted
        }
    }

    updateSession(sessionKey, data, prevSession) {
        this.sessions[prevSession] = ''
        return this.sendReadyMessage(sessionKey, data)
    }

    sendMessage(sessionKey, message) {
        const decipher = crypto.createDecipher('aes256', this.sessions[sessionKey]);
        const decrypted = decipher.update(message, 'hex', 'utf8') + decipher.final('utf8');
        console.log("Session: " + sessionKey)
        console.log("Data: " + decrypted)
        const cipher = crypto.createCipher('aes256', sessionKey);
        const encrypted = cipher.update(decrypted + ":RESPONSED", 'utf8', 'hex') + cipher.final('hex');
        return {
            message: encrypted
        }
    }
}

class Client {
    sessionKey = '';
    serverKey = '';
    preMaster = 'preMater';

    currentConnection = '';

    blocked = [];

    getHelloMessage() {
        console.log('Hello from client');
        return 'Hello from client'
    }

    setServerResponse(response, verifier) {
        const publicKey = verifier(response.cert);

        if (publicKey && !this.blocked.includes(publicKey)) {
            console.log('Valid certificate')
        } else {
            console.log('Invalid certificate')
            return {};
        }

        this.currentConnection = publicKey;

        const cipher = crypto.createCipher('aes256', publicKey);
        const encrypted = cipher.update(this.preMaster, 'utf8', 'hex') + cipher.final('hex');

        return {
            preMaster: encrypted
        }
    }

    getPreMaster(publicKey) {
        const cipher = crypto.createCipher('aes256', publicKey);
        return cipher.update(this.preMaster, 'utf8', 'hex') + cipher.final('hex');
    }

    generateSessionKey() {
        const index = Math.random() * 2000000;
        const sessionKey = `${this.preMaster}:${index.toFixed(0)}`
        console.log("Client session key: " + sessionKey)

        this.sessionKey = sessionKey;

        const cipher = crypto.createCipher('aes256', sessionKey);
        const encrypted = cipher.update('готовий', 'utf8', 'hex') + cipher.final('hex');
        return {
            clientKey: sessionKey,
            message: encrypted
        };
    }

    getMessage(message) {
        const cipher = crypto.createCipher('aes256', this.sessionKey);
        const encrypted = cipher.update(message, 'utf8', 'hex') + cipher.final('hex');
            console.log("Message: " + message)
        return {
            message: encrypted,
            session: this.serverKey
        }
    }

    blockNode(key) {
        this.blocked.push(key);

        if (this.currentConnection === key) {
            this.sessionKey = '';
            this.currentConnection = '';
            this.serverKey = '';
        }
    }
}

export function doHandShake(server, client) {
    const helloMessage = server.setHelloMessage(client.getHelloMessage());

    const { preMaster } = client.setServerResponse(helloMessage, server.verifyCert.bind(server));

    if (!preMaster) return;

    const clientSession = client.generateSessionKey();

    const serverSession = server.setPreMaster(preMaster);

    client.serverKey = serverSession.key;

    server.sendReadyMessage(serverSession.key, clientSession);
}

export function resend(server, client, messageText, prevSession) {
    const clientSession = client.generateSessionKey();

    const serverSession = server.setPreMaster(client.getPreMaster(server.publicKey));

    client.serverKey = serverSession.key;

    server.updateSession(serverSession.key, clientSession, prevSession);

    const message = client.getMessage(messageText)

    console.log("Encoded after resend: " + message.message)

    server.sendMessage(message.session, message.message)
}


const server = new Server();
server.certificate = fs.readFileSync('path/ca-certificate.pem', 'utf8');
server.publicKey = fs.readFileSync('path/ca-public-key.pem', 'utf8')
    .split('\r\n')
    .join('');

const client = new Client();

console.log("----------Common handshake-------------")

doHandShake(server, client)

const message = client.getMessage('Good')

console.log("Encoded: " + message.message)

server.sendMessage(message.session, message.message)

console.log("----------Resend-------------")

resend(server, client, 'Good', message.session)

client.blockNode(server.publicKey);

console.log("----------After block-------------")

doHandShake(server, client);
