# RTP Audio Separation

## Task Description

Implement a program that reads raw RTP packet data from a file or network interface and produces audio files.

You are provided with a PCAP file containing packets captured from an Avaya telephony system. It contains thousands of audio streams captured within a 180 second duration. Your task is to identify and write each audio stream to a separate audio file. 

Although we do not require that the program run in real time, we expect you to be aware of performance considerations and attempt to optimize your program to run close to it. You are allowed to use Python, Go, C, or C++ to implement your program. You are expected to utilize concurrency to complete this task.

Your program should accept either a network interface or capture file, and output directory as input parameters. Additional configuration should be handled using optional parameters, environment variables, and/or a configuration file. 
For example: `./audio_rtp_parser -i eno3 -o /tmp/audio -c config.yml`

You must verify that the output of your program is correct, and are expected to submit your source and testing code via a git repository. Please commit often and with adequate commit messages; how you approach and think through the problem is as important as the final outcome.

## Approach
This repo contain 2 main python script, `main.py` and `main_parallel.py`. 
Both script using `PyShark` module that wrap `Wireshark / tshark`.

`PyShark` module has limitation to read the PCAP file (doing fileCapture). In my experiment, `PyShark` FileCapture has limitation to read packet persecond (pps) with following formula `pps = 0.0021(n_packets) + 2.6299`. In other words, with increasing number of packets, more time needed to read, despite stream only 180s it finish read more than 180s. 

| packet/time (pps) |  n_packet |
|---|---|
|  21.04372093 | 8884 |
|  41.71766881 | 17779  |
|  91.09865561 |41318|

ReadStream process is colleting payload each session, detecting if there is any pair (forward-reverse stream) audio stream, detecting codec used on each session. 

So, the difference between `main.py` and `main_parallel.py` is on how to process payload extract the audio file, and if there is reverse packet (pair), it will be merge using `ffmpeg` library. In the `main.py` process extraction and merging in the same thread (main thread), in the other hand, `main_parallel.py` process extraction and merging in the difference thread (extraction thread and merging thread), proceed by queue of the RTP session (`rtp.ssrc`).   

## Requirements
- Wireshark / tshark
    ```powershell
    choco install wireshark
    ```
- ffmpeg
    ```powershell
    choco install ffmpeg
    ```
- Python 3.6+ with following modules : `Cython`, `pyshark`, `pywav`, `pydub`, and `pyyaml`
    ```bash
    pip install -r requirements.txt
    ```

## Testing Enviroment
| Label  | Value   |
|---|---|
| OS | Windows 10 Version	10.0.18363 Build 18363 |
| Memory | 16GB DDR4 |
| Processor | 4 cores Intel Core i7-8550U @1.8GHz  |

## Configuration Sample
```yaml
# config.yml
filter: rtp.ssrc==0x46873251||rtp.ssrc==0x0d730ec4
```

## Usage
- Single Thread
    ```bash
    python main.py -i file.pcap -o outdir -c config.yml
    ```
- Multi Thread
    ```bash
    python main_parallel.py -i file.pcap -o outdir -c config.yml
    ```

## Logs
If you want to see logs, check `logs` dir