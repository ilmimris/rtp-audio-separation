# RTP Audio Separation

## Description

Implement a program that reads raw RTP packet data from a file or network interface and produces audio files.

You are provided with a PCAP file containing packets captured from an Avaya telephony system. It contains thousands of audio streams captured within a 180 second duration. Your task is to identify and write each audio stream to a separate audio file. 

Although we do not require that the program run in real time, we expect you to be aware of performance considerations and attempt to optimize your program to run close to it. You are allowed to use Python, Go, C, or C++ to implement your program. You are expected to utilize concurrency to complete this task.

Your program should accept either a network interface or capture file, and output directory as input parameters. Additional configuration should be handled using optional parameters, environment variables, and/or a configuration file. 
For example: `./audio_rtp_parser -i eno3 -o /tmp/audio -c config.yml`

You must verify that the output of your program is correct, and are expected to submit your source and testing code via a git repository. Please commit often and with adequate commit messages; how you approach and think through the problem is as important as the final outcome.