//this was overkill af there are much better libraries out there and this was... a choice
import {Vector, Wiregasm} from "@goodtools/wiregasm";
//@ts-ignore
import * as wgballs from "@goodtools/wiregasm/dist/wiregasm";

import * as fs from "fs";
import path from "path";

import Long from "long";
import * as pbjs from "protobufjs";
import{ WebSocketServer } from "ws";
import { Kcp } from "./kcp";
import MTKey from "./bf/mtkey";
import "./bf/bruteforce"
import crypto from "crypto";



function getFile(name: string) {
    return fs.readFileSync(path.join(__dirname, name));
}


function loadRsaKeys(){
    let location = "../data/ys/RSAKeys.js";
    let keys = eval(getFile(location).toString());

    let keyArr: {privateKey : string, decrypt: (b:Buffer)=>Buffer}[] = [];
    for(let k of keys){
        //xml 
        let key = {
            privateKey : k,
            decrypt : (buffer: Buffer) => {
                return crypto.privateDecrypt(
                    {
                        key: k,
                        padding: crypto.constants.RSA_PKCS1_PADDING
                    },
                    buffer
                );
            }
        }
        keyArr.push(key);
    }
    return keyArr
}



// // sr specific
// const YSCmdIds = JSON.parse(getFile("../data/sr/CmdIds.json").toString());

const YSCmdIds = {};
const root = pbjs.loadSync(path.join(__dirname, "../data/sr/Empty.proto"));



function stringify(...args: any) {

    let obj = args[0];

    return JSON.stringify(obj, (key, value) => {
        if (value instanceof Long) {
            return value.toString();
        }
        if (value instanceof pbjs.util.LongBits) {

        }
        if (typeof value === "bigint") {
            return value.toString();
        }
        return value;
    }, 2);
}

function EmVecToArr<T>(vec: Vector<T>): T[] {
    let arr: T[] = [];
    for (let i = 0; i < vec.size(); i++) {
        arr.push(vec.get(i));
    }
    return arr;
}

const pcapFile = getFile("../ignorelol/3logins4.0gi.pcap");
const resultFramesFile = "../ignorelol/frames2.json";

// const pcapFile = getFile("../ignorelol/genshin3.8.pcap");
// const resultFramesFile = "../ignorelol/frames3.json";

async function parsePcap() {

    const wg = new Wiregasm();
    await wg.init(wgballs["default"], {
        locateFile: (path: string, prefix: string) => {
            console.log(`locateFile: path: ${path} prefix: ${prefix}`)
            if (path.endsWith(".data")) return "node_modules/@goodtools/wiregasm/dist/wiregasm.data";
            if (path.endsWith(".wasm")) return "node_modules/@goodtools/wiregasm/dist/wiregasm.wasm";
            return prefix + path;
        },
        // supress all unwanted logs in test-suite
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        printErr: () => { },
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        print: () => { },
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        handleStatus: () => { },
    });
    console.log("Library loaded");

    let ret = wg.load("star.pcap", pcapFile);

    console.log("loaded pcap successfully");
    console.log(ret);

    let packets = wg.frames("");

    let count = packets.frames.size();
    console.log("there are " + count + " packets");
    let frames: any[] = [];
    for (let i = 1; i <= count; i++) {
        let frame = wg.frame(i);

        let frameObj = {
            number: frame.number,
            comments: EmVecToArr(frame.comments),
            data_sources: EmVecToArr(frame.data_sources),
            tree: EmVecToArr(frame.tree),
        };


        frames.push(frameObj);
    }

    fs.writeFileSync(path.join(__dirname, resultFramesFile), stringify(frames));
    wg.destroy();
}


const initKeys = Object.fromEntries(getFile("../ysdispatchkeys.bin").toString("utf-8").split("\n").map(x=>x.split(": ")))

// console.log(initKeys)
//for me at least

const initKey = Buffer.from(initKeys['29921'], "hex");

//2641676052
const startMagic = 0x4567;

const endMagic = 0x89ab;


function getALargeNumber(obj:object){
    let value = null;
    for (let [k, v] of Object.entries(obj)) {
        if (typeof v === "bigint") {
            value = v;
        }
        if(typeof v === "number"){
            value = BigInt(v);
        }
        if (v instanceof Long) {
            value = BigInt(v.toString());
        }
    }
    return value

}

function getAllLargeStrings(obj:object){
    let values  = [];
    for(let [k,v] of Object.entries(obj)){
        if(typeof v === "string" && v.length > 100){
            values.push(v);
        }
    }
    return values;
}

function xor(buf: Buffer, key: Buffer) {
    let result = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) {
        result[i] = buf[i] ^ key[i % key.length];
    }
    return result;
}



function parseProto(cmdId: number, buf: Buffer, homemade: boolean = false) : object{
    
    if(homemade){
        return parseProtoBad1(buf);
    }
    if (YSCmdIds[cmdId] && cmdId != 0) {
        let protoName = YSCmdIds[cmdId];
        try {
            var proto = root.lookupType(protoName);
        } catch (e) {
            console.log(`proto ${protoName} not found`);
            return parseProtoBad(buf);
        }
        let message = proto.decode(buf);
        let obj = proto.toObject(message, {
            longs: Long,
            enums: String,
            bytes: String,
            defaults: true,
        });
        return obj;
    } else {
        return parseProtoBad(buf);
    }
}

import CyberChefProtobufLmao from "./Protobuf";

function parseProtoBad(buf: Buffer) {
    try{
        let x = CyberChefProtobufLmao.decode(buf, [
            "",
            true,true
        ]);
        return x||{}
        
    }catch(e){
        console.log(e);
        return {
            "unknown": buf.toString("base64"),
            "error" : e.toString() 
        }
    }
}


//homemade. workable but not particularly useful
function parseProtoBad1(buf: Buffer) {
    const reader = new pbjs.BufferReader(buf);
    let obj: any = {};
    // console.log(buf.toString("base64"));
    while (reader.pos < reader.len) {
        let fieldNo = reader.int32();
        let wireType = fieldNo & 0x7;
        let fieldId = fieldNo >> 3;
        switch (wireType) {
            case 0:
                //varint
                let val = reader.uint64();

                obj["field" + fieldId] = BigInt(new Long(val.low, val.high, val.unsigned).toString());
                break;
            case 1:
                //64 bit
                let val64 = reader.double();
                obj["field" + fieldId] = val64;

                break;
            case 2:
                //length delimited
                // let len = reader.uint32();
                let subBuf = Buffer.from(reader.bytes());
                // obj["field" + fieldId] = parseProtoIsh(subBuf);
                obj["field" + fieldId] = subBuf.toString("base64");

                break;
            case 5:
                //32 bit
                let val32 = reader.float();
                obj["field" + fieldId] = val32;
                break;
            default:
                break;
        }

        // console.log(reader.pos, reader.len)
    }
    return obj;
}


type TrafficPacket = {
    cmdId: number,
    data: Buffer,
    seq: number,
    obj: any,
    source: "client" | "server"
};


class TrafficInstance {
    constructor(public callback: (pack: TrafficPacket) => void, public RSAKeys: {privateKey : string, decrypt: (b:Buffer)=>Buffer}[]) { }
    clientKcp: Kcp = null!;
    serverKcp: Kcp = null!;
    clientPort = 0;

    seq = 0;

    lastPack: object = null!;
    curKey = initKey;

    curr_ts = 0n;
    last_rand_key = 0n;

    bruteforcer = new KeyBruteforcer();
    kcpRecv(kcp: Kcp) {
        let size = kcp.peekSize();
        if (size <= 0) return {
            success: false
        };
        let buf = Buffer.alloc(size);
        let read = kcp.recv(buf);
        if (read != size) return {
            success: false
        };
        // buf is a full packet
        return {
            buf,
            success: true
        };
    }

    reset(){
        this.clientKcp = null!;
        this.serverKcp = null!;
        this.clientPort = 0;
        this.seq = 0;
        this.lastPack = null!;
        this.curKey = initKey;
        this.curr_ts = 0n;
        this.last_rand_key = 0n;
    }
    processHandshake(data:Buffer, sourceport:number){
        let magic = data.readUInt32BE(0);
        let conv = data.readUInt32BE(4);
        let token = data.readUInt32BE(8);
        switch (magic) {
            case 0xFF:
                this.reset();
                //connect 
                this.clientPort = sourceport;
                console.log("client connect handshake")
                break;
            case 0x145:
                this.clientKcp = new Kcp(conv, token, () => { });
                this.serverKcp = new Kcp(conv, token, () => { });
                console.log("kcp created")
                break;
            case 0x194:
                break;
        }
    }

    processPacket(frame: Buffer) {
        let data = frame;

        //cut off 34 bytes of header
        // data = data.subarray(34);

        //cut off 20 bytes for a different header (todo maybe figure out the network stack thing automatically)
        data = data.subarray(20);
        //
        let sourceport = data.readUInt16BE(0);
        let destport = data.readUInt16BE(2);
        // ok now udp is irrelevant
        data = data.subarray(8);

        if (data.length == 20) {
            return this.processHandshake(data, sourceport);
        }
            //hamdshake packet
        

        if (!this.clientKcp || !this.serverKcp) {
            //no handshake etc yet, so ignore everything
            return;
        }

        const _status = (this.clientPort == sourceport) ? this.clientKcp.input(data) : this.serverKcp.input(data);

        let shouldContinue = true;
        while (shouldContinue) {
            //yeah theres definitely a simpler way to write this but im too lazy to think
            let serverRecv = this.kcpRecv(this.serverKcp);
            let clientRecv = this.kcpRecv(this.clientKcp);
            if (!serverRecv.success && !clientRecv.success) {
                shouldContinue = false;
                break;
            }
            if (serverRecv.success) {
                let ret = <TrafficPacket>this.parseKcpPacket(serverRecv.buf);
                ret.source = "server";
                this.callback(ret);
            }
            if (clientRecv.success) {
                let ret = <TrafficPacket>this.parseKcpPacket(clientRecv.buf);
                ret.source = "client";
                this.callback(ret);
            }
        }

        
    }






    attemptToRecoverKey(tokenrsp:object){
        let strings = getAllLargeStrings(tokenrsp);
        for(let key of this.RSAKeys){
            for(let string of strings){
                try{
                    //yeah...
                    let buf = Buffer.from(Buffer.from(string, "base64").toString("utf8"), "base64");
                    let res = key.decrypt(buf);
                    return res;
                }catch(e){
                    // console.log(e);
                }
            }
        }

    }

    parseKcpPacket(buf: Buffer){
        //check magic

        // console.log(Buffer.from([buf[0] ^ 0x45, buf[1] ^ 0x67]).readUint16BE(0)) // 29921
        let xored = xor(buf, this.curKey);

        let magic = xored.readUInt16BE(0);
        if (magic != startMagic) {
            //xor
            //key is not default dispatched one anymore
            //try to find key seed (big number in root lvl of object)


            let res = this.attemptToRecoverKey(this.lastPack);

            let serverRandSeed = res.readBigInt64BE(0);


            // 1695405728428n: 6747613285518788750n
            // 1695405728426 : 6747613285518788750
            let key = this.bruteforcer.bruteforce(buf, this.curr_ts, serverRandSeed)
            if(key){
                this.curKey = key;
                console.log("found key!");
            }else{
                console.log("no key found :(");
                process.exit(0);
            }

            xored = xor(buf, this.curKey);
            magic = xored.readUInt16BE(0);
            if (magic != startMagic) {
                console.log("still no magic");
                console.log(magic)
                process.exit(0);
            }
        }

        let cmdId = xored.readUInt16BE(2);
        let packetHeaderLen = xored.readUInt16BE(4);
        let dataLen = xored.readUInt32BE(6);

        let packetHead = xored.subarray(10, 10 + packetHeaderLen);

        

        let packetHeadData = parseProtoBad(packetHead);
        this.curr_ts = getALargeNumber(packetHeadData) as bigint;
        //the largest nunmber is the timestamp

        // console.log(packetHeadData);


        let dataSlice = xored.subarray(10 + packetHeaderLen, 10 + packetHeaderLen + dataLen);

        let magic2 = xored.readUInt16BE(10 + packetHeaderLen + dataLen);
        if (packetHeaderLen + dataLen + 12 != xored.length) {
            console.log("weird packet length discrepancy? reported: %s, actual: %s", packetHeaderLen + dataLen + 12, xored.length);
        }

        if (magic2 != endMagic) {
            console.log(`magic2 was wrong: ${magic2}`)
            process.exit(0);
        }

        let obj = parseProto(cmdId, dataSlice,true);


        this.lastPack = obj;
        // obj = parseProto(cmdId, dataSlice, false);
        

        return {
            cmdId,
            data: dataSlice,
            obj,
            seq: this.seq++,
        }
    }

}


// /*

async function main1() {
    
    //using a preprocessed json file (from above )
    const frames: Buffer[] = (() => {
        let f = JSON.parse(getFile(resultFramesFile).toString("utf8"));
        return f.map((x: any) => Buffer.from(x.data_sources[0].data, "base64"));
    })()

    let traffic = new TrafficInstance((obj: TrafficPacket) => {
        console.log(`PACKET cmdId: ${YSCmdIds[obj.cmdId] ?? obj.cmdId} sender : ${obj.source}`)

        console.log(obj.obj)
    }, loadRsaKeys());
    console.log(frames.length)
    for (let frame of frames) {
        traffic.processPacket(frame);
    }
}

//smh no typedefs
//@ts-ignore 
import * as cap from "cap";
import { rawListeners } from "process";
import KeyBruteforcer from "./bf/keybruteforcer";



async function main2() {
    // let c = new cap.Cap();
    // let device = cap.Cap.findDevice("192.168.11.143");
    // let filter = 'udp port 23301';
    // let buffer = Buffer.alloc(65535);

    // let linkType = c.open(device, filter, 10 * 1024 * 1024, buffer);
    // c.setMinBytes && c.setMinBytes(0);


    // let ws = new WebSocketServer({
    //     //'ws://127.0.0.1:40510'
    //     port: 40510
    // })

    // //ping
    // //move sync
    // let ignored = ["PlayerHeartBeatScRsp", "PlayerHeartBeatCsReq", "SceneEntityMoveCsReq", "SceneEntityMoveScRsp"]

    // let traffic = new TrafficInstance((obj: TrafficPacket) => {
    //     console.log(`seq: ${obj.seq.toString().padStart(5)}, cmdId: ${YSCmdIds[obj.cmdId]}, obj ${stringify(obj.obj)}`)

    //     if (YSCmdIds[obj.cmdId] && ignored.includes(YSCmdIds[obj.cmdId])) {
    //         return;
    //     }
    //     let iridiumObj = {
    //         cmd: "PacketNotify",
    //         data: [
    //             {
    //                 packetID: obj.cmdId,
    //                 protoName: YSCmdIds[obj.cmdId],
    //                 object: obj.obj,
    //                 packet: obj.data.toString("base64"),
    //                 source: obj.source == "client" ? 1 : 0,
    //             }
    //         ]
    //     }
    //     ws.clients.forEach(x => {
    //         x.send(stringify(iridiumObj));
    //     });



    // });

    // c.on('packet', function (nbytes: number, trunc: boolean) {
    //     if (linkType === 'ETHERNET') {
    //         //clone buf
    //         let buf = Buffer.alloc(nbytes);
    //         buffer.copy(buf, 0, 0, nbytes);

    //         traffic.processPacket(buf);
    //     } else {
    //         console.log('Non-ethernet packet?');
    //         console.log(linkType)
    //     }
    // })
}

// main2();

// main1();


export {
    main1,
    parsePcap
}

// */

