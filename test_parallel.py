import pytest
import pyshark
from main_parallel import *


def test_concatPayload():
    sample_packet = [
        "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff",
        "fe:fe:fe:fe:fe:fe:fe:fe:fe:fe:fe:fe:fe:fe:fe:fe",
    ]
    assert (
        concatPayload(sample_packet)
        == "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe"
    )

def test_openPCAP():
    sample_pcap_file = os.path.join("samples", "pair_session.pcap")
    filter_type = 'rtp'
    cap = openPCAP(sample_pcap_file, filter_type)

    assert type(cap) == pyshark.capture.file_capture.FileCapture

def test_packetPayload2RawAudio():
    with open('samples/payload1', 'r') as payload:
        audio = packetPayload2RawAudio(payload.read())
        assert type(audio) == bytearray

def test_raw2wav():
    with open('samples/payload1', 'r') as payload:
        audio = packetPayload2RawAudio(payload.read())
        raw2wav(audio, fn='samples/payload1.wav', fmt=7)
    assert os.path.exists('samples/payload1.wav')


def test_mergeAudio():
    sample_pair_list = {"192.168.255.100:3916": {'dst': '172.20.0.182:6614', 'src_ssrc': '0x0d7a0f4c', 'dst_ssrc': '0x48161a90'}}
    outdir = './samples'
    for pair in sample_pair_list:
        audios = openPairAudio(sample_pair_list[pair], outdir)
        if audios:
            first, second, fn = audios
            output = os.path.join(outdir, fn)
            combinePair(first, second, output)
    
    assert os.path.exists(output)
