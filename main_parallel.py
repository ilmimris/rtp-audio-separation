import os
import yaml
import argparse
import pyshark
import pywav
import pydub
from pydub import AudioSegment
from pathlib import Path
import multiprocessing

from threading import Thread
from queue import Queue

from time import sleep
import time

import logging as logger
from datetime import date

today = date.today()

# Init logger
date = today.strftime("%d-%m-%Y")
logger.basicConfig(
    filename=os.path.join(os.getcwd(), f"rtp_{date}.log"),
    filemode="a",
    format="%(asctime)s %(name)-12s (%(threadName)-10s) %(levelname)-8s %(message)s",
    datefmt="%d-%m-%Y %H:%M:%S",
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

args = vars(ap.parse_args())


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


def getRTPlayer(packet):
    return packet[3]


def getUDPlayer(packet):
    return packet[2]


def getIPlayer(packet):
    return packet[1]


def getCodec(rtp: pyshark.packet.layer.Layer) -> str:
    p_type_dict = {"0": "PCMU", "3": "GSM", "8": "PCMA", "9": "G722"}
    codec = p_type_dict[rtp.p_type]
    return codec


def usePyWavCodec(codec: str) -> int:
    pywav_codec_dict = {"PCMU": 7, "PCMA": 6, "PCM": 1}
    return pywav_codec_dict[codec]


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


def concatPayload(packet: list) -> str:
    return " ".join(packet).replace(":", " ")


def readStream(
    cap: pyshark.capture.file_capture.FileCapture,
    rtp_list: dict = {},
    rtp_codec_list: dict = {},
    pair_list: dict = {},
):
    start_time = time.time()
    countPacket = 0
    bandwidth = 0
    for packet in cap:
        countPacket +=1
        bandwidth = bandwidth + int(packet.length)
        try:
            rtp = getRTPlayer(packet)
            pair_list = collectingPairSession(packet, pair_list)
            rtp_codec_list = collectingCodecBySession(rtp, rtp_codec_list)
            rtp_list = collectingPayloadBySession(rtp, rtp_list)
        except Exception as e:
            logger.error(f"error: {e}")
    
    logger.info(f"Packet nr {countPacket}")
    logger.info(f"Byte per second {bandwidth}")
    logger.info("finish read in {} seconds".format(time.time() - start_time))
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


def converterWorker(queue, outdir, rtp_codec_list, rtp_list, pair_list):
    logger.debug("converterWorker Started")
    while True:
        rtp_ssrc = queue.get()
        
        Path(outdir).mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Converting {rtp_ssrc}")
        audioSeparation(rtp_ssrc, rtp_list, rtp_codec_list, outdir=outdir)
        logger.info(f"Finish convert session {rtp_ssrc} raw audio to wav")
        queue.task_done()

def mergingWorker(queue, outdir, pair_list):
    logger.debug("mergingWorker Started")
    while True:
        pair = queue.get()

        logger.info(f"Merging {pair}")
        audios = openPairAudio(pair_list[pair], outdir)
        
        outdir = outdir+'/merge'
        Path(outdir).mkdir(parents=True, exist_ok=True)
        logger.debug(audios)
        if audios:
            first, second, fn = audios
            combinePair(first, second, os.path.join(outdir, fn))
        queue.task_done()


def main():
    rtp_list, rtp_codec_list, pair_list = {}, {}, {}
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

    # Parallel Processing using multithread
    q_convert = Queue()
    q_merge = Queue()

    # turn-on the worker thread
    threads = []
    for i in range(int(NUM_CORES*0.5)):
        t1 = Thread(target=converterWorker, args=(q_convert, outdir, rtp_codec_list, rtp_list, pair_list, ), daemon=True)
        t2 = Thread(target=mergingWorker, args=(q_merge, outdir, pair_list, ), daemon=True)
        threads.append(t1)
        threads.append(t2)
        t1.start()
        t2.start()

    # queueStream(cap, queue)

    logger.info(f"Converting raw audio to wav")
    for rtp_ssrc in rtp_list:
        q_convert.put(rtp_ssrc)
    logger.info(f"Finish convert raw audio to wav")
    
    # combine pair if any
    logger.info(f"Merging pair wav into one wav")
    for pair in pair_list:
        q_merge.put(pair)
    
    # block until all tasks are done
    q_convert.join()
    q_merge.join()


if __name__ == "__main__":
    main()
    logger.info(f"Finish")