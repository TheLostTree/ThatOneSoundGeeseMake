import { Frame, Vector, Wiregasm, WiregasmLib } from "@goodtools/wiregasm";

//@ts-ignore
import * as wgballs from "@goodtools/wiregasm/dist/wiregasm";

import * as fs from "fs";
import Long from "long";

function EmVecToArr<T>(vec: Vector<T>): T[] {
    let arr : T[] = [];
    for(let i = 0; i < vec.size(); i++) {
        arr.push(vec.get(i));
    }
    return arr;
}

const pcapFile = fs.readFileSync("starrail1.2networkdumpone.pcap");
const buildTestOverrides = () => {
    return {
      locateFile: (path : string, prefix : string) => {
        console.log(`locateFile: path: ${path} prefix: ${prefix}`)
        if (path.endsWith(".data")) return "node_modules/@goodtools/wiregasm/dist/wiregasm.data";
        if (path.endsWith(".wasm")) return "node_modules/@goodtools/wiregasm/dist/wiregasm.wasm";
        return prefix + path;
      },
      // supress all unwanted logs in test-suite
      // eslint-disable-next-line @typescript-eslint/no-empty-function
      printErr: () => {},
      // eslint-disable-next-line @typescript-eslint/no-empty-function
      print: () => {},
      // eslint-disable-next-line @typescript-eslint/no-empty-function
      handleStatus: () => {},
    };
};
async function main() {

    const wg = new Wiregasm();
    await wg.init(wgballs["default"], buildTestOverrides());
    console.log("Library loaded");

    let ret = wg.load("star.pcap", pcapFile);

    console.log("loaded pcap successfully");
    console.log(ret);

    let packets = wg.frames("");
    
    let count = packets.frames.size();
    console.log("there are " + count + " packets");
    let frames :any[] = [];
    for(let i = 1; i <= count; i++) {
        let frame = wg.frame(i);
        
        let frameObj = {
            number : frame.number,
            comments: EmVecToArr(frame.comments),
            data_sources: EmVecToArr(frame.data_sources),
            tree: EmVecToArr(frame.tree),
        };


        frames.push(frameObj);
    }

    fs.writeFileSync("frames.json", JSON.stringify(frames, null, 2));
    wg.destroy();
}

// main();

const initKey = fs.readFileSync("srdispatchkey.bin");

//2641676052
const startMagic = 0x9d74c714;

const endMagic = 0xd7a152c8;

import { Kcp } from "./kcp";


import { BufferReader , util} from "protobufjs";
import MTKey from "./bf/mtkey";


function xor(buf: Buffer, key: Buffer){
    let result = Buffer.alloc(buf.length);
    for(let i = 0; i < buf.length; i++){
        result[i] = buf[i] ^ key[i % key.length];
    }
    return result;
}

let lastPack :object = null!;


let curKey = initKey;

function parseKcpPacket(buf: Buffer){
    //check magic
    let xored = xor(buf, curKey);

    let magic = xored.readUInt32BE(0);
    if(magic != startMagic){
        //xor
        //key is not default dispatched one anymore
        //try to find key seed seed
        console.log(`magic was ${magic}`)
        let value = -1n;
        for(let [k, v] of Object.entries(lastPack)){
            if(typeof v === "bigint"){
                value = v;
            }
            if(value > 10000000000n){
                console.log(value)
                let key = MTKey.fromSeedSingleSeed(BigInt(value)).keybytes;
                curKey = key;
            }
        }

        if(value == -1n){
            //i give up :pensive:
            process.exit(0);

        }
        
    }else{
        let cmdId = xored.readUInt16BE(4);
        let packetHeaderLen = xored.readUInt16BE(6);
        let dataLen = xored.readUInt32BE(8);

        if(packetHeaderLen + dataLen + 16 != xored.length){
            console.log("%s, %s",packetHeaderLen + dataLen + 16 , xored.length);
        }
        let dataSlice = xored.subarray(12 + packetHeaderLen, 12 + packetHeaderLen + dataLen);

        let obj = parseProtoIsh(dataSlice);

        console.log(`cmdId: ${cmdId}, obj: ${JSON.stringify(obj)}`)
        lastPack = obj;
    };
}


function parseProtoIsh(buf:Buffer){
    const reader = new BufferReader(buf);
    let obj : any  = {};

    // console.log(buf.toString("base64"));
    while(reader.pos < reader.len){
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

        console.log(reader.pos, reader.len)
    }

    return obj;
}


function getFrames(){
    let frames = JSON.parse(fs.readFileSync("frames.json", "utf8"));


    return frames.map(x=>Buffer.from(x.data_sources[0].data, "base64"));
}



async function main1() {

    //if you run a websocket or something with an actual libpcap handle, you can just replace this and modify it a teensy bit :D
    const frames : Buffer[] = getFrames();
    let clientKcp : Kcp = null!;
    let serverKcp : Kcp = null!;

    let clientPort = 0;
    while(frames.length > 0) {
        let frame = frames.shift()!;
        let data = frame;

        //cut off 34 bytes of header
        data = data.subarray(34);
        //
        let sourceport = data.readUInt16BE(0);
        let destport = data.readUInt16BE(2);
        // ok now udp is irrelevant
        data = data.subarray(8);

        if(data.length == 20){
            //hamdshake packet
            let magic = data.readUInt32BE(0);
            let conv = data.readUInt32BE(4);
            let token = data.readUInt32BE(8);
            switch (magic) {
                case 0xFF:
                    //connect 
                    clientPort = sourceport;
                    console.log("client connect handshake")
                    break;
                case 0x145:
                    clientKcp = new Kcp(conv, token, ()=>{});
                    serverKcp = new Kcp(conv, token, ()=>{});
                    console.log("kcp created")
                    break;
                case 0x194:
                    break;
            }
        }else{
            clientPort == sourceport ? clientKcp.input(data) : serverKcp.input(data);

            for(let kcp of [clientKcp, serverKcp]){
                while (true) {
                    let size = kcp.peekSize();
                    if(size <= 0) break;
                    let buf = Buffer.alloc(size);
                    let read = kcp.recv(buf);
                    if(read != size) break;
                    // buf is a full packet
    
                    parseKcpPacket(buf);
                    
                } 
            }
           
        }
    }





}


main1();