import os
# import yaml
# import argparse
import pyshark
import pywav

# construct the argument parser and parse the arguments
# ap = argparse.ArgumentParser(description='RTP Audio Parser')
# ap.add_argument("-i", "--input", required=True, help="input PCAP file or device (eno1)")
# ap.add_argument("-o", "--output", required=True, help="path/to/output file")
# ap.add_argument("-c", "--config", required=True, help="parser configuration path/to/config.yml")

# args = vars(ap.parse_args())

rtp_list = {}
rtp_codec_list = {}

def collectingPayloadBySession(rtp: pyshark.packet.layer.Layer
    , container: list) -> list: 
    if (container.get(rtp.ssrc, None) == None): container[rtp.ssrc] = []
    if rtp.payload: container[rtp.ssrc].append(rtp.payload)
    return container

def collectingCodecBySession(rtp: pyshark.packet.layer.Layer
    , container: list) -> list:
    if (container.get(rtp.ssrc, None) == None): container[rtp.ssrc] = []
    if rtp.p_type: container[rtp.ssrc] = getCodec(rtp)
    return container

def getRTPlayer(frame):
    return frame[3]

def getCodec(rtp: pyshark.packet.layer.Layer)-> str : 
    p_type_dict = {
        '0': 'PCMU',
        '3': 'GSM',
        '8': 'PCMA',
        '9': 'G722'
    }
    codec = p_type_dict[rtp.p_type]
    return codec

def usePyWavCodec(codec: str) -> int:
    pywav_codec_dict = {
        'PCMU': 7,
        'PCMA': 6,
        'PCM': 1
    }
    return pywav_codec_dict[codec]

def concatPayload(packet: list) -> str:
    return ' '.join(packet).replace(":"," ")

def packetPayload2RawAudio(payload: str) -> bytearray:
    return bytearray.fromhex(payload)

def raw2wav(audio: bytearray, fn: str
            , c:int=1, br:int=8000, bps:int=8
            , fmt:int=8):
    wave_write = pywav.WavWrite(fn, c, br, bps, fmt)
    wave_write.write(audio)
    wave_write.close()
    print(f"Finished converting raw audio to wav: {fn}")

def openPCAP(pcap_file: str, display_filter) -> pyshark.capture.file_capture.FileCapture:
    print(f"Scraping: {pcap_file} with filter '{display_filter}'")
    return pyshark.FileCapture(pcap_file, display_filter=display_filter)

def readStream(cap: pyshark.capture.file_capture.FileCapture):
    for frame in cap:
        try:
            rtp             = getRTPlayer(frame) 
            rtp_codec_list  = collectingCodecBySession(rtp, rtp_codec_list)
            rtp_list        = collectingPayloadBySession(rtp, rtp_list)
        except:
            pass

def audioSeparation(session):
    rtp_packet = rtp_list[session]
    codec = rtp_codec_list[session]
    fmt = usePyWavCodec(codec)
    payload = concatPayload(rtp_packet)
    audio = packetPayload2RawAudio(payload)
    raw2wav(audio, fn=f'{session}.wav', fmt=fmt)

if __name__ == "__main__":
    pcap_file = (os.path.join('../test_180s.pcap'))
    filter_type = "rtp.ssrc==0x5b6835b7"

    cap = openPCAP(pcap_file, filter_type)

    readStream(cap)

    for rtp_ssrc in rtp_list:
        audioSeparation(rtp_ssrc)

    print("\nFinished outputing raw audio")