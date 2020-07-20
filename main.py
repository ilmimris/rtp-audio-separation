import os
import yaml
import argparse
import pyshark
import pywav
import pydub
from pydub import AudioSegment

import multiprocessing
from joblib import Parallel, delayed

import logging as logger
from datetime import date
import time

today = date.today()

# Init logger
date = today.strftime("%d-%m-%Y")
logger.basicConfig(
    filename=os.path.join(os.getcwd(), f"rtp_{date}.log"),
    filemode="a",
    format="%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
    datefmt="%d-%m-%Y %H:%M",
    level=logger.DEBUG,
)


DEBUG = False
NUM_CORES = multiprocessing.cpu_count()

# construct the argument parser and parse the arguments
ap = argparse.ArgumentParser(description="RTP Audio Parser")
ap.add_argument(
    "-i", "--input", required=True, help="input PCAP file or network interface (eno1)"
)
ap.add_argument("-o", "--outdir", required=True, help="path/to/output directory")
ap.add_argument(
    "-c", "--config", required=False, help="parser configuration path/to/config.yml"
)


def loadconfig(configfile):
    with open(configfile, "r") as stream:
        try:
            config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            logger.error(exc)
    return config


def collectingPayloadBySession(rtp: pyshark.packet.layer.Layer, container):
    if container.get(rtp.ssrc, None) == None:
        container[rtp.ssrc] = []
    if rtp.payload:
        container[rtp.ssrc].append(rtp.payload)
    return container


def collectingCodecBySession(rtp: pyshark.packet.layer.Layer, container):
    if container.get(rtp.ssrc, None) == None:
        container[rtp.ssrc] = []
    if rtp.p_type:
        container[rtp.ssrc] = getCodec(rtp)
    return container


def getRTPlayer(frame):
    return frame[3]


def getUDPlayer(frame):
    return frame[2]


def getIPlayer(frame):
    return frame[1]


def getCodec(rtp: pyshark.packet.layer.Layer) -> str:
    p_type_dict = {"0": "PCMU", "3": "GSM", "8": "PCMA", "9": "G722"}
    codec = p_type_dict[rtp.p_type]
    return codec


def usePyWavCodec(codec: str) -> int:
    pywav_codec_dict = {"PCMU": 7, "PCMA": 6, "PCM": 1}
    return pywav_codec_dict[codec]


def concatPayload(packet: list) -> str:
    return " ".join(packet).replace(":", " ")


def packetPayload2RawAudio(payload: str) -> bytearray:
    return bytearray.fromhex(payload)


def raw2wav(
    audio: bytearray, fn: str, c: int = 1, br: int = 8000, bps: int = 8, fmt: int = 8
):
    wave_write = pywav.WavWrite(fn, c, br, bps, fmt)
    wave_write.write(audio)
    wave_write.close()
    logger.info(f"Finished converting raw audio to wav: {fn}")


def openPCAP(
    pcap_file: str, display_filter
) -> pyshark.capture.file_capture.FileCapture:
    logger.info(f"Scraping: {pcap_file} with filter '{display_filter}'")
    cap = pyshark.FileCapture(pcap_file, display_filter=display_filter, debug=DEBUG)
    return cap


def collectingPairSession(packet: pyshark.packet.packet.Packet, container):
    ip = getIPlayer(packet)
    udp = getUDPlayer(packet)
    rtp = getRTPlayer(packet)

    src = ":".join([ip.src, udp.port])
    dst = ":".join([ip.dst, udp.dstport])

    # logger.info(f"check first {container}")

    # Check if already have pair
    if src in container:
        if container[src].get("dst_ssrc", None) != None:
            return container

    # Check pair first
    if dst in container:
        if container[dst]["dst"] == src:
            container[dst]["dst_ssrc"] = rtp.ssrc
            # logger.info(f"pair found: {container[dst]['src_ssrc']} , {rtp.ssrc}")
            return container

    if container.get(src, None) == None:
        container[src] = {}
    if rtp.payload:
        container[src] = {"dst": dst, "src_ssrc": rtp.ssrc, "dst_ssrc": None}
    # logger.info(f"pair_list {container}")
    return container


# def processStream(frame):
#     try:
#         rtp             = getRTPlayer(frame)
#         rtp_codec_list  = collectingCodecBySession(rtp, rtp_codec_list)
#         rtp_list        = collectingPayloadBySession(rtp, rtp_list)
#         pair_list       = collectingPairSession(frame, pair_list)
#     except Exception as e:
#         logger.info(f"error: {e}")
#     return rtp_list, rtp_codec_list, pair_list


def readStream(
    cap: pyshark.capture.file_capture.FileCapture,
    rtp_list: dict = {},
    rtp_codec_list: dict = {},
    pair_list: dict = {},
):
    start_time = time.time()
    countPacket = 0
    bandwidth = 0
    for frame in cap:
        countPacket += 1
        bandwidth = bandwidth + int(frame.length)
        try:
            rtp = getRTPlayer(frame)
            pair_list = collectingPairSession(frame, pair_list)
            rtp_codec_list = collectingCodecBySession(rtp, rtp_codec_list)
            rtp_list = collectingPayloadBySession(rtp, rtp_list)
        except Exception as e:
            logger.error(f"error: {e}")

    total_time = time.time() - start_time
    pps = countPacket / total_time

    logger.info(f"Finish scrap: {pcap_file}")
    logger.info(f"Packet nr {countPacket}")
    logger.info(f"Packet per second {pps}")
    logger.info(f"Byte per second {bandwidth}")
    logger.info("--- finish in {} seconds ---".format(total_time))
    return rtp_list, rtp_codec_list, pair_list


def audioSeparation(session, rtp_list, rtp_codec_list, outdir=""):
    logger.info(f"separation audio in session (ssrc): {session}")
    rtp_packet = rtp_list[session]
    codec = rtp_codec_list[session]
    fmt = usePyWavCodec(codec)
    payload = concatPayload(rtp_packet)
    audio = packetPayload2RawAudio(payload)
    output = os.path.join(outdir, f"{session}.wav")
    logger.info(f"converting audio in session (ssrc): {session} to {output}")
    raw2wav(audio, fn=output, fmt=fmt)


def openPairAudio(pair_list, outdir):
    logger.debug(pair_list)
    au1 = pair_list.get("src_ssrc")
    au2 = pair_list.get("dst_ssrc", None)
    if au2 == None:
        return False

    first = AudioSegment.from_file(os.path.join(outdir, f"{au1}.wav"), format="wav")
    second = AudioSegment.from_file(os.path.join(outdir, f"{au2}.wav"), format="wav")
    fn = "-".join([au1, f"{au2}.wav"])
    return first, second, fn


def combinePair(
    first: pydub.audio_segment.AudioSegment,
    second: pydub.audio_segment.AudioSegment,
    fn: str,
    position=0,
):
    combined = first.overlay(second, position)
    combined.export(fn, format="wav")


if __name__ == "__main__":
    args = vars(ap.parse_args())

    pcap_file = (
        args["input"] if (args["input"]) else (os.path.join("../test_180s.pcap"))
    )
    outdir = args["outdir"] if (args["outdir"]) else os.getcwd()
    config = loadconfig(args["config"]) if (args["config"]) else None

    filter_type = config["filter"] if config else "rtp"

    logger.info(f"Start capturing {pcap_file}")
    cap = openPCAP(pcap_file, filter_type)

    rtp_list, rtp_codec_list, pair_list = readStream(cap)
    logger.info(f"Finish capture {pcap_file}")

    logger.info(f"Converting raw audio to wav")
    for rtp_ssrc in rtp_list:
        audioSeparation(rtp_ssrc, rtp_list, rtp_codec_list, outdir)
    logger.info(f"Finish convert raw audio to wav")

    # combine pair if any
    logger.info(f"Merging pair wav into one wav")
    for pair in pair_list:
        audios = openPairAudio(pair_list[pair], outdir)
        # logger.debug(audios)
        if audios:
            first, second, fn = audios
            combinePair(first, second, os.path.join(outdir, fn))
    logger.info(f"Finish")
