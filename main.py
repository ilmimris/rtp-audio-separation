import os
import yaml
import argparse
import pyshark
import pywav

DEBUG = False

# construct the argument parser and parse the arguments
ap = argparse.ArgumentParser(description='RTP Audio Parser')
ap.add_argument("-i", "--input", required=True, help="input PCAP file or network interface (eno1)")
ap.add_argument("-o", "--outdir", required=True, help="path/to/output directory")
ap.add_argument("-c", "--config", required=False, help="parser configuration path/to/config.yml")

args = vars(ap.parse_args())

# rtp_list = {}
# rtp_codec_list = {}

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
    cap = pyshark.FileCapture(pcap_file, display_filter=display_filter, debug=DEBUG)
    return cap

def loadconfig(configfile):
        with open(configfile, 'r') as stream:
            try:
                config = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)
        return config

def readStream(cap: pyshark.capture.file_capture.FileCapture, rtp_list:dict={}, rtp_codec_list:dict={}):
    for frame in cap:
        try:
            rtp             = getRTPlayer(frame) 
            rtp_codec_list  = collectingCodecBySession(rtp, rtp_codec_list)
            rtp_list        = collectingPayloadBySession(rtp, rtp_list)
        except Exception as e:
            print(e)

    print(f"Finish scrap: {pcap_file}")
    return rtp_list, rtp_codec_list

def audioSeparation(session, rtp_list, rtp_codec_list, outdir=''):
    print(f"separation audio in session (ssrc): {session}")
    rtp_packet = rtp_list[session]
    codec = rtp_codec_list[session]
    fmt = usePyWavCodec(codec)
    payload = concatPayload(rtp_packet)
    audio = packetPayload2RawAudio(payload)
    output = os.path.join(outdir, f'{session}.wav')
    print(f"converting audio in session (ssrc): {session} to {output}")
    raw2wav(audio, fn=output, fmt=fmt)

if __name__ == "__main__":
    pcap_file   = args['input'] if (args['input']) else (os.path.join('../test_180s.pcap'))
    outdir      = args['outdir'] if (args['outdir']) else os.getcwd()
    config      = loadconfig(args['config']) if (args['config']) else None
    
    # filter_type = "rtp.ssrc==0x5b6835b7"
    filter_type = config['filter'] if config else 'rtp'

    cap = openPCAP(pcap_file, filter_type)

    rtp_list, rtp_codec_list = readStream(cap)

    for rtp_ssrc in rtp_list:
        audioSeparation(rtp_ssrc, rtp_list, rtp_codec_list, outdir)