namespace IpLab.Core
open System
open System.Collections.ObjectModel
open System.ComponentModel
open Microsoft.FSharp.Quotations
open Microsoft.FSharp.Quotations.Patterns
open System.Net.Sockets
open System.Net
open System.Text

type IPPacket = {
    Destination : string;
    Source : string;
    Version : int;
    IHL : int;
    DifferentiatedServices : int;
    TotalLength : int;
    Identification : int;
    Flags : int;
    FragmentOffset : int;
    TTL : int;
    Protocol : int;
    HeaderChecksum : int;
    Payload : string;
}


type NetworkSniffer(endpoint : IPEndPoint) =
    let _socket : Socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP)
    let _endpoint : IPEndPoint = endpoint
    let inArray : array<byte> = [| byte 1; byte 0; byte 0;  byte 0|] 
    let outArray : array<byte> = [| byte 0; byte 0; byte 0;  byte 0|]
    do _socket.Bind(_endpoint) |> ignore
    do _socket.IOControl(IOControlCode.ReceiveAll, inArray, outArray) |> ignore

    let ExtractPayload buffer start count protocol =    
        buffer |> 
        Array.map(fun x -> byte x) |> 
        Array.skip(start + match protocol with | 17 -> 8 | _ -> 0 ) |> 
        Array.take (count - match protocol with | 17 -> 8 | _ -> 0 )


    member x.Sniff() =
        let bufferByte : array<byte> = Array.zeroCreate 65565
        let receivedBytes = _socket.Receive(bufferByte)
        let buffer = bufferByte |> Array.map(fun(x)->int x)
        let version = buffer.[0] >>> 4
        let ihl = buffer.[0] &&& 0x0f
        let diffServices = buffer.[1]
        let totalLength = (buffer.[2] <<< 8) + buffer.[3]
        let id = (buffer.[4] <<< 8) + buffer.[5]
        let flags = buffer.[6] >>> 5
        let fragment = ((buffer.[6] &&& 0x1f) <<< 8) + buffer.[7]
        let ttl = buffer.[8]
        let protocol = buffer.[9]
        let crc = (buffer.[10] <<< 8) + buffer.[11]
        let source= buffer.[12].ToString() + "." + buffer.[13].ToString() + "." + buffer.[14].ToString() + "." + buffer.[15].ToString()
        let dest = buffer.[16].ToString() + "." + buffer.[17].ToString() + "." + buffer.[18].ToString() + "." + buffer.[19].ToString()
        
        let payload = ExtractPayload buffer (ihl*4) (receivedBytes - 4*ihl) protocol
        let header = match protocol with 
                            | 17 -> "Source Port : " + ((buffer.[ihl*4] <<< 8) + buffer.[ihl*4 + 1]).ToString() + "\r\n" +
                                    "Destination Port : " + ((buffer.[ihl*4 + 2] <<< 8) + buffer.[ihl*4 + 3]).ToString() + "\r\n" + 
                                    "Length : " + ((buffer.[ihl*4 + 4] <<< 8) + buffer.[ihl*4 + 5]).ToString() + "\r\n" +
                                    "Checksum : " + ((buffer.[ihl*4 + 6] <<< 8) + buffer.[ihl*4 + 7]).ToString() + "\r\n"
                            | _ -> ""
        let payloadWithHeader  = header + Encoding.Default.GetString(payload);

        {
            Version = version;
            IHL = ihl;
            DifferentiatedServices = diffServices;
            TotalLength = totalLength;
            Identification = id;
            Flags = flags;
            FragmentOffset = fragment;
            TTL = ttl;
            Protocol = protocol;
            HeaderChecksum = crc;
            Source = source;
            Destination = dest; 
            Payload = payloadWithHeader
        }

    member x.SniffAsync() = async { return x.Sniff()} |> Async.StartAsTask

