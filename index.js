import { createServer } from "http"
import { readFile } from "fs/promises";

const origins = new Map()

createServer(async (req, res) => {
    try {
        const ip = req.socket.remoteAddress;
        const registered = origins.get(ip);
        if (req.url == "/mw/vpn/api/set" || !registered) {
            if (req.method == "POST") {
                origins.set(ip, form body param url) and then navigate the user to the pathname of the url
            }

            // html
            res.end(await readFile("index.html")); //form to set the url and show some history
        }
    } catch (error) {
        res.end(error);
    }

    pipe all requests raw to the server(it have to support all protocols), raw tcp pipes.working for websocets too 
}).listen(80)